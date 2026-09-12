#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <grp.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/compiler_specific.h"
#include "base/containers/flat_map.h"
#include "base/containers/span.h"
#include "base/files/scoped_file.h"
#include "base/logging.h"
#include "base/memory/free_deleter.h"
#include "base/memory/raw_ptr.h"
#include "base/posix/eintr_wrapper.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_split.h"
#include "base/task/single_thread_task_executor.h"
#include "base/threading/thread.h"
#include "ctf/ctf.mojom.h"
#include "mojo/core/embedder/embedder.h"
#include "mojo/core/embedder/scoped_ipc_support.h"
#include "mojo/public/cpp/bindings/pending_remote.h"
#include "mojo/public/cpp/bindings/remote.h"
#include "mojo/public/cpp/platform/platform_channel.h"
#include "mojo/public/cpp/system/invitation.h"
#include "mojo/public/cpp/system/message_pipe.h"

namespace {

constexpr uint64_t kPipeName = 0;

constexpr size_t kPreviewBytes = 32;
constexpr int kPlayerReadFd = 100;
constexpr int kPlayerWriteFd = 101;

constexpr uid_t kSandboxUid = 65534;
constexpr gid_t kSandboxGid = 65534;
constexpr uint16_t kListenPort = 8888;
constexpr size_t kMaxNameLength = 24;
constexpr size_t kMaxLineLength = 64 * 1024;

void DropPrivileges() {
  if (getuid() != 0) {

    return;
  }
  PCHECK(setgroups(0, nullptr) == 0) << "setgroups failed";
  PCHECK(setresgid(kSandboxGid, kSandboxGid, kSandboxGid) == 0)
      << "setresgid failed";
  PCHECK(setresuid(kSandboxUid, kSandboxUid, kSandboxUid) == 0)
      << "setresuid failed";

  CHECK_NE(setuid(0), 0) << "privileges were not actually dropped";
  CHECK_EQ(getuid(), kSandboxUid);
  CHECK_EQ(geteuid(), kSandboxUid);
}

ctf::mojom::FileRequestPtr MakeRequest(const std::vector<uint8_t>& token,
                                       const std::string& filename,
                                       const std::vector<uint8_t>& data) {
  auto request = ctf::mojom::FileRequest::New();
  request->token = token;
  request->filename = filename;
  request->size = static_cast<uint32_t>(data.size());
  request->data = data;
  return request;
}

struct FileEntry {
  char name[kMaxNameLength];
  uint32_t size;
  void (*render)(const FileEntry* entry, const uint8_t* data, uint32_t length);
};

using FileEntryPtr = std::unique_ptr<FileEntry, base::FreeDeleter>;
using BufferPtr = std::unique_ptr<uint8_t, base::FreeDeleter>;

void PrintFile(const FileEntry* entry, const uint8_t* data, uint32_t length) {
  const size_t shown = length < 16 ? length : 16;
  UNSAFE_BUFFERS(const base::span<const uint8_t> preview(data, shown););
  LOG(INFO) << "[client] rendered " << entry->name << ": " << length
            << " bytes starting " << base::HexEncode(preview);
}

class Connection {
 public:

  Connection(int in_fd, int out_fd, mojo::Remote<ctf::mojom::Registry> registry)
      : in_fd_(in_fd), out_fd_(out_fd), registry_(std::move(registry)) {}

  Connection(const Connection&) = delete;
  Connection& operator=(const Connection&) = delete;

  void Serve() {
    Send("ctf file manager. HELP for commands.");
    std::string line;
    while (ReadLine(&line)) {
      if (!Dispatch(line)) {
        break;
      }
    }
  }

 private:
  void Send(const std::string& text) {
    const std::string out = text + "\n";
    size_t sent = 0;
    while (sent < out.size()) {
      const ssize_t n = HANDLE_EINTR(
          write(out_fd_, out.data() + sent, out.size() - sent));
      if (n <= 0) {
        return;
      }
      sent += static_cast<size_t>(n);
    }
  }

  bool ReadLine(std::string* line) {
    line->clear();
    for (;;) {
      char c = 0;
      const ssize_t n = HANDLE_EINTR(read(in_fd_, &c, 1));
      if (n <= 0) {
        return false;
      }
      if (c == '\n') {
        if (!line->empty() && line->back() == '\r') {
          line->pop_back();
        }
        return true;
      }
      if (line->size() >= kMaxLineLength) {
        return false;
      }
      line->push_back(c);
    }
  }

  bool Dispatch(const std::string& line) {
    const std::vector<std::string> argv = base::SplitString(
        line, " ", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);
    if (argv.empty()) {
      return true;
    }
    const std::string& cmd = argv[0];

    if (cmd == "QUIT") {
      Send("OK bye");
      return false;
    }
    if (cmd == "HELP") {
      Send("OK commands: REGISTER <user> | LOGIN <hex token> | MKDIR <name> | "
           "CD <name>|/ | CREATE <name> <hex> | WRITE <name> <hex> | "
           "READ <name> | CAT <path> | DELETE <name> | LIST | QUIT");
      return true;
    }
    if (cmd == "REGISTER") {
      return DoRegister(argv);
    }
    if (!registered_) {
      Send("ERR register first");
      return true;
    }
    if (cmd == "MKDIR") {
      return DoMkdir(argv);
    }
    if (cmd == "CD") {
      return DoCd(argv);
    }
    if (cmd == "CREATE") {
      return DoCreate(argv);
    }
    if (cmd == "WRITE") {
      return DoWrite(argv);
    }
    if (cmd == "READ") {
      return DoRead(argv);
    }
    if (cmd == "DELETE") {
      return DoDelete(argv);
    }
    if (cmd == "LIST") {
      return DoList();
    }

    if (cmd == "LOGIN") {
      return DoLogin(argv);
    }
    if (cmd == "CAT") {
      return DoCat(argv);
    }
    Send("ERR unknown command");
    return true;
  }

  bool DoRegister(const std::vector<std::string>& argv) {
    if (argv.size() != 2) {
      Send("ERR usage: REGISTER <username>");
      return true;
    }
    ctf::mojom::RegisterResultPtr registration;
    if (!registry_->Register(argv[1], &registration)) {
      Send("ERR broker went away");
      return false;
    }
    if (!registration->success) {
      Send("ERR " + registration->message);
      return true;
    }
    token_ = registration->token;

    ctf::mojom::FolderResultPtr opened;
    if (!registry_->OpenRoot(token_, &opened)) {
      Send("ERR broker went away");
      return false;
    }
    if (opened->error != ctf::mojom::FileError::kOk) {
      Send("ERR " + opened->message);
      return true;
    }
    root_.Bind(std::move(opened->folder));
    current_ = &root_;
    registered_ = true;
    Send("OK " + registration->message +
         " token=" + base::HexEncode(token_));
    return true;
  }

  bool DoMkdir(const std::vector<std::string>& argv) {
    if (argv.size() != 2) {
      Send("ERR usage: MKDIR <name>");
      return true;
    }
    ctf::mojom::FolderResultPtr made;
    if (!(*current_)->CreateFolder(MakeRequest(token_, argv[1], {}), &made)) {
      Send("ERR broker went away");
      return false;
    }
    if (made->error != ctf::mojom::FileError::kOk) {
      Send("ERR " + made->message);
      return true;
    }
    folders_[argv[1]].Bind(std::move(made->folder));
    Send("OK " + made->message);
    return true;
  }

  bool DoCd(const std::vector<std::string>& argv) {
    if (argv.size() != 2) {
      Send("ERR usage: CD <name>|/");
      return true;
    }
    if (argv[1] == "/") {
      current_ = &root_;
      Send("OK at /");
      return true;
    }
    const auto it = folders_.find(argv[1]);
    if (it == folders_.end()) {
      Send("ERR no such folder in this session (MKDIR it first)");
      return true;
    }
    current_ = &it->second;
    Send("OK at " + argv[1]);
    return true;
  }

  bool DoCreate(const std::vector<std::string>& argv) {
    if (argv.size() < 2 || argv.size() > 3) {
      Send("ERR usage: CREATE <name> <hex>");
      return true;
    }
    if (argv[1].size() >= kMaxNameLength) {
      Send("ERR name too long");
      return true;
    }
    std::vector<uint8_t> data;
    if (argv.size() == 3 && !base::HexStringToBytes(argv[2], &data)) {
      Send("ERR bad hex");
      return true;
    }

    ctf::mojom::FileResultPtr result;
    if (!(*current_)->WriteFile(MakeRequest(token_, argv[1], data), &result)) {
      Send("ERR broker went away");
      return false;
    }
    if (result->error != ctf::mojom::FileError::kOk) {
      Send("ERR " + result->message);
      return true;
    }

    FileEntryPtr entry(static_cast<FileEntry*>(malloc(sizeof(FileEntry))));
    if (!entry) {
      Send("ERR out of memory");
      return true;
    }
    UNSAFE_BUFFERS(
        strncpy(entry->name, argv[1].c_str(), kMaxNameLength - 1););
    entry->name[kMaxNameLength - 1] = '\0';
    entry->size = static_cast<uint32_t>(data.size());
    entry->render = &PrintFile;
    entries_.push_back(std::move(entry));

    Send("OK created " + argv[1] + " size " +
         base::NumberToString(data.size()));
    return true;
  }

  bool DoWrite(const std::vector<std::string>& argv) {
    if (argv.size() != 3) {
      Send("ERR usage: WRITE <name> <hex>");
      return true;
    }
    FileEntry* entry = Find(argv[1]);
    if (!entry) {
      Send("ERR no such file");
      return true;
    }
    std::vector<uint8_t> data;
    if (!base::HexStringToBytes(argv[2], &data)) {
      Send("ERR bad hex");
      return true;
    }

    ctf::mojom::FileResultPtr result;
    if (!(*current_)->WriteFile(MakeRequest(token_, argv[1], data), &result)) {
      Send("ERR broker went away");
      return false;
    }
    if (result->error != ctf::mojom::FileError::kOk) {
      Send("ERR " + result->message);
      return true;
    }
    Send("OK wrote " + base::NumberToString(data.size()) + " bytes");
    return true;
  }

  [[gnu::noinline]] bool DoRead(const std::vector<std::string>& argv) {
    if (argv.size() != 2) {
      Send("ERR usage: READ <name>");
      return true;
    }
    FileEntry* entry = Find(argv[1]);
    if (!entry) {
      Send("ERR no such file");
      return true;
    }

    ctf::mojom::FileResultPtr result;
    if (!(*current_)->ReadFile(MakeRequest(token_, argv[1], {}), &result)) {
      Send("ERR broker went away");
      return false;
    }
    if (result->error != ctf::mojom::FileError::kOk) {
      Send("ERR " + result->message);
      return true;
    }

    const uint32_t length = static_cast<uint32_t>(result->data.size());
    const std::vector<uint8_t>& in = result->data;

    if (entry->size <= kPreviewBytes) {
      uint8_t preview[kPreviewBytes];
      uint8_t* out = preview;
      UNSAFE_BUFFERS(for (uint32_t i = 0; i < length; ++i) { out[i] = in[i]; });
      entry->render(entry, preview, length);
    } else {
      BufferPtr buffer(static_cast<uint8_t*>(malloc(entry->size)));
      if (!buffer) {
        Send("ERR out of memory");
        return true;
      }
      uint8_t* out = buffer.get();
      UNSAFE_BUFFERS(for (uint32_t i = 0; i < length; ++i) { out[i] = in[i]; });
      entry->render(entry, buffer.get(), length);
    }
    Send("OK read " + base::NumberToString(length) + " " +
         base::HexEncode(result->data));
    return true;
  }

  bool DoDelete(const std::vector<std::string>& argv) {
    if (argv.size() != 2) {
      Send("ERR usage: DELETE <name>");
      return true;
    }
    ctf::mojom::FileResultPtr result;
    if (!(*current_)->DeleteFile(MakeRequest(token_, argv[1], {}), &result)) {
      Send("ERR broker went away");
      return false;
    }
    if (result->error != ctf::mojom::FileError::kOk) {
      Send("ERR " + result->message);
      return true;
    }

    for (auto it = entries_.begin(); it != entries_.end(); ++it) {
      if (argv[1] == (*it)->name) {
        entries_.erase(it);
        break;
      }
    }
    Send("OK " + result->message);
    return true;
  }

  bool DoLogin(const std::vector<std::string>& argv) {
    std::vector<uint8_t> token;
    if (argv.size() != 2 || !base::HexStringToBytes(argv[1], &token)) {
      Send("ERR usage: LOGIN <hex token>");
      return true;
    }
    ctf::mojom::FolderResultPtr opened;
    if (!registry_->OpenRoot(token, &opened)) {
      Send("ERR broker went away");
      return false;
    }
    if (opened->error != ctf::mojom::FileError::kOk) {
      Send("ERR " + opened->message);
      return true;
    }
    token_ = token;
    root_.reset();
    root_.Bind(std::move(opened->folder));
    current_ = &root_;
    folders_.clear();
    Send("OK " + opened->message);
    return true;
  }

  bool DoCat(const std::vector<std::string>& argv) {
    if (argv.size() != 2) {
      Send("ERR usage: CAT <path>");
      return true;
    }
    ctf::mojom::FileResultPtr result;
    if (!(*current_)->ReadFile(MakeRequest(token_, argv[1], {}), &result)) {
      Send("ERR broker went away");
      return false;
    }
    if (result->error != ctf::mojom::FileError::kOk) {
      Send("ERR " + result->message);
      return true;
    }
    Send("OK " + std::string(result->data.begin(), result->data.end()));
    return true;
  }

  bool DoList() {
    std::string out = "OK";
    for (const auto& entry : entries_) {
      out += " " + std::string(entry->name) + ":" +
             base::NumberToString(entry->size);
    }
    Send(out);
    return true;
  }

  FileEntry* Find(const std::string& name) {
    for (const auto& entry : entries_) {
      if (name == entry->name) {
        return entry.get();
      }
    }
    return nullptr;
  }

  const int in_fd_;
  const int out_fd_;
  mojo::Remote<ctf::mojom::Registry> registry_;

  bool registered_ = false;
  std::vector<uint8_t> token_;
  mojo::Remote<ctf::mojom::Folder> root_;
  base::flat_map<std::string, mojo::Remote<ctf::mojom::Folder>> folders_;
  raw_ptr<mojo::Remote<ctf::mojom::Folder>> current_ = nullptr;

  std::vector<FileEntryPtr> entries_;
};

base::ScopedFD Listen(uint16_t port) {
  base::ScopedFD listener(socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0));
  CHECK(listener.is_valid()) << "socket() failed";

  const int one = 1;
  setsockopt(listener.get(), SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

  sockaddr_in addr = {};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port = htons(port);
  CHECK_EQ(bind(listener.get(), reinterpret_cast<sockaddr*>(&addr),
                sizeof(addr)),
           0)
      << "bind(" << port << ") failed";
  CHECK_EQ(listen(listener.get(), 1), 0) << "listen failed";
  return listener;
}

}

int main(int argc, char** argv) {

  DropPrivileges();

  base::AtExitManager exit_manager;
  base::CommandLine::Init(argc, argv);
  base::SingleThreadTaskExecutor main_task_executor;

  mojo::core::Init();

  base::Thread ipc_thread("mojo-ipc");
  CHECK(ipc_thread.StartWithOptions(
      base::Thread::Options(base::MessagePumpType::IO, 0)));
  mojo::core::ScopedIPCSupport ipc_support(
      ipc_thread.task_runner(),
      mojo::core::ScopedIPCSupport::ShutdownPolicy::CLEAN);

  mojo::PlatformChannelEndpoint endpoint =
      mojo::PlatformChannel::RecoverPassedEndpointFromCommandLine(
          *base::CommandLine::ForCurrentProcess());
  CHECK(endpoint.is_valid()) << "no mojo platform channel on command line";

  mojo::IncomingInvitation invitation =
      mojo::IncomingInvitation::Accept(std::move(endpoint));
  mojo::ScopedMessagePipeHandle pipe = invitation.ExtractMessagePipe(kPipeName);
  CHECK(pipe.is_valid()) << "failed to extract message pipe";

  mojo::Remote<ctf::mojom::Registry> registry(
      mojo::PendingRemote<ctf::mojom::Registry>(std::move(pipe), 0));
  LOG(INFO) << "[sandboxee] connected to broker";

  if (getenv("CTF_STDIO")) {
    LOG(INFO) << "[sandboxee] serving the player on fds " << kPlayerReadFd
              << "/" << kPlayerWriteFd;
    Connection connection(kPlayerReadFd, kPlayerWriteFd, std::move(registry));
    connection.Serve();
  } else {
    base::ScopedFD listener = Listen(kListenPort);
    LOG(INFO) << "[sandboxee] listening on 0.0.0.0:" << kListenPort;

    base::ScopedFD client(
        HANDLE_EINTR(accept(listener.get(), nullptr, nullptr)));
    if (!client.is_valid()) {
      LOG(ERROR) << "[sandboxee] accept failed";
      return 1;
    }
    LOG(INFO) << "[sandboxee] player connected";
    Connection connection(client.get(), client.get(), std::move(registry));
    connection.Serve();
  }

  LOG(INFO) << "[sandboxee] player disconnected";
  return 0;
}
