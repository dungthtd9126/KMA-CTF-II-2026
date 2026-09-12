#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <array>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/containers/span.h"
#include "base/files/file.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/files/scoped_file.h"
#include "base/functional/bind.h"
#include "base/logging.h"
#include "base/memory/raw_ptr.h"
#include "base/no_destructor.h"
#include "base/path_service.h"
#include "base/posix/eintr_wrapper.h"
#include "base/process/launch.h"
#include "base/process/process.h"
#include "base/run_loop.h"
#include "base/strings/string_number_conversions.h"
#include "base/task/single_thread_task_executor.h"
#include "base/threading/thread.h"
#include "ctf/ctf.mojom.h"
#include "mojo/core/embedder/embedder.h"
#include "mojo/core/embedder/scoped_ipc_support.h"
#include "mojo/public/cpp/bindings/pending_receiver.h"
#include "mojo/public/cpp/bindings/pending_remote.h"
#include "mojo/public/cpp/bindings/receiver.h"
#include "mojo/public/cpp/bindings/unique_receiver_set.h"
#include "mojo/public/cpp/platform/platform_channel.h"
#include "mojo/public/cpp/system/invitation.h"
#include "mojo/public/cpp/system/message_pipe.h"

namespace {

constexpr uint64_t kPipeName = 0;

constexpr int kPlayerReadFd = 100;
constexpr int kPlayerWriteFd = 101;

constexpr char kAdminUser[] = "assmin";

constexpr char kStorageParent[] = "/tmp/ao";

constexpr size_t kInstanceNameLength = 16;
base::FilePath SandboxeePath() {
  base::FilePath exe;
  CHECK(base::PathService::Get(base::DIR_EXE, &exe));
  return exe.Append(FILE_PATH_LITERAL("sandboxee"));
}

std::vector<uint8_t> RandomBytes(size_t count) {
  base::File urandom(base::FilePath(FILE_PATH_LITERAL("/dev/urandom")),
                     base::File::FLAG_OPEN | base::File::FLAG_READ);
  CHECK(urandom.IsValid()) << "cannot open /dev/urandom";

  std::vector<uint8_t> bytes(count);
  CHECK(urandom.ReadAtCurrentPosAndCheck(base::span(bytes)))
      << "short read from /dev/urandom";
  return bytes;
}

std::string RandomName(size_t length) {
  static constexpr char kAlphabet[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  constexpr size_t kAlphabetSize = sizeof(kAlphabet) - 1;

  constexpr uint8_t kRejectAtOrAbove = 256 - (256 % kAlphabetSize);

  std::string name;
  while (name.size() < length) {
    for (uint8_t byte : RandomBytes(length)) {
      if (byte >= kRejectAtOrAbove) {
        continue;
      }
      name.push_back(kAlphabet[byte % kAlphabetSize]);
      if (name.size() == length) {
        break;
      }
    }
  }
  return name;
}

const std::string& StorageRoot() {
  static const base::NoDestructor<std::string> root(
      std::string(kStorageParent) + "/" + RandomName(kInstanceNameLength));
  return *root;
}

constexpr size_t kTokenBytes = 32;

constexpr size_t kDiskNameLength = 16;

constexpr size_t kMaxFileBytes = 1000;

constexpr size_t kMaxUsernameLength = 65536;
constexpr size_t kMaxNameLength = 255;

constexpr size_t kMaxReadBytes = 1u << 20;

bool TokensEqual(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
  if (a.size() != b.size()) {
    return false;
  }
  uint8_t diff = 0;
  for (size_t i = 0; i < a.size(); ++i) {
    diff |= static_cast<uint8_t>(a[i] ^ b[i]);
  }
  return diff == 0;
}

bool IsSingleComponentName(const std::string& name) {
  return !name.empty() && name.size() <= kMaxNameLength &&
         name.find('/') == std::string::npos &&
         name.find('\0') == std::string::npos && name != "." && name != "..";
}

std::optional<std::vector<uint8_t>> RawReadFile(const base::FilePath& path) {
  base::ScopedFD fd(
      HANDLE_EINTR(open(path.value().c_str(), O_RDONLY | O_CLOEXEC)));
  if (!fd.is_valid()) {
    return std::nullopt;
  }

  std::vector<uint8_t> data;
  std::array<uint8_t, 4096> chunk;
  for (;;) {
    const ssize_t got =
        HANDLE_EINTR(read(fd.get(), chunk.data(), chunk.size()));
    if (got < 0) {
      return std::nullopt;
    }
    if (got == 0) {
      return data;
    }
    const base::span<const uint8_t> read_bytes =
        base::span(chunk).first(static_cast<size_t>(got));
    if (data.size() + read_bytes.size() > kMaxReadBytes) {
      return std::nullopt;
    }
    data.insert(data.end(), read_bytes.begin(), read_bytes.end());
  }
}

bool RawWriteFile(const base::FilePath& path, base::span<const uint8_t> data) {
  base::ScopedFD fd(HANDLE_EINTR(open(path.value().c_str(),
                                      O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                                      0644)));
  if (!fd.is_valid()) {
    return false;
  }
  base::span<const uint8_t> remaining = data;
  while (!remaining.empty()) {
    const ssize_t written =
        HANDLE_EINTR(write(fd.get(), remaining.data(), remaining.size()));
    if (written <= 0) {
      return false;
    }
    remaining = remaining.subspan(static_cast<size_t>(written));
  }
  return true;
}

bool RawCreateDirectory(const base::FilePath& path) {
  return mkdir(path.value().c_str(), 0755) == 0;
}

bool RawCreateParents(const base::FilePath& path) {
  const std::string& full = path.value();
  const size_t last_slash = full.rfind('/');
  if (last_slash == std::string::npos || last_slash == 0) {

    return true;
  }

  for (size_t i = 1; i <= last_slash; ++i) {
    if (i != last_slash && full[i] != '/') {
      continue;
    }
    const std::string prefix = full.substr(0, i);
    if (mkdir(prefix.c_str(), 0755) != 0 && errno != EEXIST) {
      return false;
    }
  }
  return true;
}

bool RawRemove(const base::FilePath& path) {
  if (unlink(path.value().c_str()) == 0) {
    return true;
  }

  return rmdir(path.value().c_str()) == 0;
}

bool RawExists(const base::FilePath& path) {
  return access(path.value().c_str(), F_OK) == 0;
}

base::FilePath JoinUnchecked(const base::FilePath& directory,
                             const std::string& name) {
  if (!name.empty() && name.front() == '/') {
    return base::FilePath(name);
  }
  return base::FilePath(directory.value() + "/" + name);
}

struct Account {
  std::string name;
  std::vector<uint8_t> token;
  bool is_admin = false;

  std::map<std::string, std::string> entries;
};

ctf::mojom::FileResultPtr FileOk(const std::string& message) {
  auto result = ctf::mojom::FileResult::New();
  result->error = ctf::mojom::FileError::kOk;
  result->message = message;
  return result;
}

ctf::mojom::FileResultPtr FileFail(ctf::mojom::FileError error,
                                   const std::string& message) {
  auto result = ctf::mojom::FileResult::New();
  result->error = error;
  result->message = message;
  return result;
}

ctf::mojom::FolderResultPtr FolderFail(ctf::mojom::FileError error,
                                       const std::string& message) {
  auto result = ctf::mojom::FolderResult::New();
  result->error = error;
  result->message = message;
  return result;
}

class Broker {
 public:
  virtual ~Broker() = default;

  virtual Account* AccountForToken(const std::vector<uint8_t>& token) = 0;

  virtual std::string MintDiskName() = 0;

  virtual mojo::PendingRemote<ctf::mojom::Folder> BindFolder(
      const std::string& account_name,
      const std::string& logical_prefix,
      const base::FilePath& disk_dir) = 0;
};

class FolderImpl : public ctf::mojom::Folder {
 public:
  FolderImpl(Broker* broker,
             std::string account_name,
             std::string logical_prefix,
             base::FilePath disk_dir)
      : broker_(broker),
        account_name_(std::move(account_name)),
        logical_prefix_(std::move(logical_prefix)),
        disk_dir_(std::move(disk_dir)) {}

  FolderImpl(const FolderImpl&) = delete;
  FolderImpl& operator=(const FolderImpl&) = delete;
  ~FolderImpl() override = default;

  void CreateFolder(ctf::mojom::FileRequestPtr request,
                    CreateFolderCallback callback) override {
    Account* account = Authenticate(request->token);
    if (!account) {
      std::move(callback).Run(
          FolderFail(ctf::mojom::FileError::kBadToken, BadTokenMessage()));
      return;
    }

    base::FilePath path;
    std::string key;
    std::string disk_name;
    if (account->is_admin) {

      path = JoinUnchecked(disk_dir_, request->filename);
      if (RawExists(path)) {
        std::move(callback).Run(
            FolderFail(ctf::mojom::FileError::kExists, "already exists"));
        return;
      }
      if (!RawCreateParents(path)) {
        std::move(callback).Run(FolderFail(ctf::mojom::FileError::kIoError,
                                           "cannot create parent folders"));
        return;
      }
    } else {
      if (!IsSingleComponentName(request->filename)) {
        std::move(callback).Run(FolderFail(ctf::mojom::FileError::kBadName,
                                           "name must be a single component"));
        return;
      }
      key = LogicalKey(request->filename);
      if (account->entries.contains(key)) {
        std::move(callback).Run(
            FolderFail(ctf::mojom::FileError::kExists, "already exists"));
        return;
      }
      disk_name = broker_->MintDiskName();
      path = disk_dir_.Append(disk_name);
    }

    if (!RawCreateDirectory(path)) {
      std::move(callback).Run(
          FolderFail(ctf::mojom::FileError::kIoError, "mkdir failed"));
      return;
    }
    if (!account->is_admin) {
      account->entries[key] = disk_name;
    }

    auto result = ctf::mojom::FolderResult::New();
    result->error = ctf::mojom::FileError::kOk;
    result->message = "created folder " + request->filename;
    result->folder = broker_->BindFolder(account_name_,
                                         LogicalKey(request->filename), path);

    LOG(INFO) << "[broker] " << account_name_ << " mkdir "
              << LogicalKey(request->filename);
    std::move(callback).Run(std::move(result));
  }

  void WriteFile(ctf::mojom::FileRequestPtr request,
                 WriteFileCallback callback) override {
    Account* account = Authenticate(request->token);
    if (!account) {
      std::move(callback).Run(
          FileFail(ctf::mojom::FileError::kBadToken, BadTokenMessage()));
      return;
    }

    if (request->size != request->data.size()) {
      std::move(callback).Run(
          FileFail(ctf::mojom::FileError::kSizeMismatch,
                   "size " + base::NumberToString(request->size) +
                       " does not match " +
                       base::NumberToString(request->data.size()) +
                       " bytes of data"));
      return;
    }

    if (!account->is_admin && request->data.size() > kMaxFileBytes) {
      std::move(callback).Run(
          FileFail(ctf::mojom::FileError::kTooLarge,
                   "file limit is " + base::NumberToString(kMaxFileBytes) +
                       " bytes"));
      return;
    }

    base::FilePath path;
    if (account->is_admin) {

      path = JoinUnchecked(disk_dir_, request->filename);
      if (!RawExists(path) && !RawCreateParents(path)) {
        std::move(callback).Run(FileFail(ctf::mojom::FileError::kIoError,
                                         "cannot create parent folders"));
        return;
      }
    } else {
      if (!IsSingleComponentName(request->filename)) {
        std::move(callback).Run(FileFail(ctf::mojom::FileError::kBadName,
                                         "name must be a single component"));
        return;
      }

      const std::string key = LogicalKey(request->filename);
      const auto it = account->entries.find(key);
      const std::string disk_name = it != account->entries.end()
                                        ? it->second
                                        : broker_->MintDiskName();
      account->entries[key] = disk_name;
      path = disk_dir_.Append(disk_name);
    }

    if (!RawWriteFile(path, base::span(request->data))) {
      std::move(callback).Run(
          FileFail(ctf::mojom::FileError::kIoError, "write failed"));
      return;
    }

    LOG(INFO) << "[broker] " << account_name_ << " write "
              << LogicalKey(request->filename) << " ("
              << request->data.size() << " bytes)";
    std::move(callback).Run(FileOk(
        "wrote " + base::NumberToString(request->data.size()) + " bytes"));
  }

  void ReadFile(ctf::mojom::FileRequestPtr request,
                ReadFileCallback callback) override {
    Account* account = Authenticate(request->token);
    if (!account) {
      std::move(callback).Run(
          FileFail(ctf::mojom::FileError::kBadToken, BadTokenMessage()));
      return;
    }

    std::optional<base::FilePath> path =
        ResolveExisting(*account, request->filename);
    if (!path.has_value()) {
      std::move(callback).Run(
          FileFail(ctf::mojom::FileError::kNotFound, "no such file"));
      return;
    }

    std::optional<std::vector<uint8_t>> data = RawReadFile(*path);
    if (!data.has_value()) {
      std::move(callback).Run(
          FileFail(ctf::mojom::FileError::kIoError, "read failed"));
      return;
    }

    LOG(INFO) << "[broker] " << account_name_ << " read "
              << LogicalKey(request->filename) << " (" << data->size()
              << " bytes)";
    auto result =
        FileOk("read " + base::NumberToString(data->size()) + " bytes");
    result->data = std::move(*data);
    std::move(callback).Run(std::move(result));
  }

  void DeleteFile(ctf::mojom::FileRequestPtr request,
                  DeleteFileCallback callback) override {
    Account* account = Authenticate(request->token);
    if (!account) {
      std::move(callback).Run(
          FileFail(ctf::mojom::FileError::kBadToken, BadTokenMessage()));
      return;
    }

    std::optional<base::FilePath> path =
        ResolveExisting(*account, request->filename);
    if (!path.has_value()) {
      std::move(callback).Run(
          FileFail(ctf::mojom::FileError::kNotFound, "no such file"));
      return;
    }

    if (!RawRemove(*path)) {
      std::move(callback).Run(FileFail(ctf::mojom::FileError::kIoError,
                                       "delete failed (a folder must be empty)"));
      return;
    }
    if (!account->is_admin) {
      account->entries.erase(LogicalKey(request->filename));
    }

    LOG(INFO) << "[broker] " << account_name_ << " delete "
              << LogicalKey(request->filename);
    std::move(callback).Run(FileOk("deleted " + request->filename));
  }

 private:

  Account* Authenticate(const std::vector<uint8_t>& token) {
    Account* account = broker_->AccountForToken(token);
    if (!account || account->name != account_name_) {
      return nullptr;
    }
    return account;
  }

  std::string BadTokenMessage() const {
    return "unknown token, or token does not own this folder";
  }

  std::string LogicalKey(const std::string& name) const {
    return logical_prefix_.empty() ? name : logical_prefix_ + "/" + name;
  }

  std::optional<base::FilePath> ResolveExisting(const Account& account,
                                                const std::string& name) {
    if (account.is_admin) {
      const base::FilePath path = JoinUnchecked(disk_dir_, name);
      if (!RawExists(path)) {
        return std::nullopt;
      }
      return path;
    }

    if (!IsSingleComponentName(name)) {
      return std::nullopt;
    }

    const auto it = account.entries.find(LogicalKey(name));
    if (it == account.entries.end()) {
      return std::nullopt;
    }
    return disk_dir_.Append(it->second);
  }

  const raw_ptr<Broker> broker_;

  const std::string account_name_;
  const std::string logical_prefix_;
  const base::FilePath disk_dir_;
};

class RegistryImpl : public ctf::mojom::Registry, public Broker {
 public:
  RegistryImpl() = default;

  RegistryImpl(const RegistryImpl&) = delete;
  RegistryImpl& operator=(const RegistryImpl&) = delete;
  ~RegistryImpl() override = default;

  void Register(const std::string& username,
                RegisterCallback callback) override {
    EnsureInitialized();

    auto result = ctf::mojom::RegisterResult::New();
    result->success = false;

    if (username.empty() || username.size() > kMaxUsernameLength) {
      result->message = "cannot register user: username must be 1 to " +
                        base::NumberToString(kMaxUsernameLength) + " bytes";
      std::move(callback).Run(std::move(result));
      return;
    }

    if (!IsSingleComponentName(username)) {
      result->message = "cannot register " + username + " user";
      std::move(callback).Run(std::move(result));
      return;
    }

    if (accounts_.contains(username)) {

      result->message = "cannot register " + username + " user";
      LOG(INFO) << "[broker] register rejected: '" << username
                << "' already exists";
      std::move(callback).Run(std::move(result));
      return;
    }

    const Account& account = CreateAccount(username);
    result->success = true;
    result->message = "registered " + username;
    result->token = account.token;
    LOG(INFO) << "[broker] registered '" << username << "'";
    std::move(callback).Run(std::move(result));
  }

  void OpenRoot(const std::vector<uint8_t>& token,
                OpenRootCallback callback) override {
    EnsureInitialized();

    Account* account = AccountForToken(token);
    if (!account) {
      std::move(callback).Run(
          FolderFail(ctf::mojom::FileError::kBadToken, "unknown token"));
      return;
    }

    auto result = ctf::mojom::FolderResult::New();
    result->error = ctf::mojom::FileError::kOk;
    result->message = "opened /" + account->name;
    result->folder =
        BindFolder(account->name, std::string(), UserRoot(*account));

    LOG(INFO) << "[broker] " << account->name << " opened root";
    std::move(callback).Run(std::move(result));
  }

  Account* AccountForToken(const std::vector<uint8_t>& token) override {
    if (token.size() != kTokenBytes) {
      return nullptr;
    }
    for (auto& [name, account] : accounts_) {
      if (TokensEqual(account.token, token)) {
        return &account;
      }
    }
    return nullptr;
  }

  std::string MintDiskName() override {
    for (;;) {
      std::string name = RandomName(kDiskNameLength);
      if (used_disk_names_.insert(name).second) {
        return name;
      }
    }
  }

  mojo::PendingRemote<ctf::mojom::Folder> BindFolder(
      const std::string& account_name,
      const std::string& logical_prefix,
      const base::FilePath& disk_dir) override {
    mojo::PendingRemote<ctf::mojom::Folder> remote;
    folders_.Add(std::make_unique<FolderImpl>(this, account_name,
                                              logical_prefix, disk_dir),
                 remote.InitWithNewPipeAndPassReceiver());
    return remote;
  }

 private:

  void EnsureInitialized() {
    if (initialized_) {
      return;
    }
    initialized_ = true;

    const base::FilePath root(StorageRoot());
    if (base::PathExists(root)) {
      CHECK(base::DeletePathRecursively(root))
          << "cannot clear storage root " << StorageRoot();
    }
    CHECK(base::CreateDirectory(root))
        << "cannot create storage root " << StorageRoot();
    LOG(INFO) << "[broker] storage root " << StorageRoot();

    Account& admin = CreateAccount(kAdminUser);
    admin.is_admin = true;
    LOG(INFO) << "[broker] admin account '" << kAdminUser << "' created ("
              << admin.token.size() << "-byte token)";
  }

  static base::FilePath UserRoot(const Account& account) {
    return base::FilePath(StorageRoot()).Append(account.name);
  }

  Account& CreateAccount(const std::string& name) {
    Account account;
    account.name = name;
    account.token = RandomBytes(kTokenBytes);
    auto [it, inserted] = accounts_.emplace(name, std::move(account));
    CHECK(inserted);
    CHECK(base::CreateDirectory(UserRoot(it->second)))
        << "cannot create folder for " << name;
    return it->second;
  }

  bool initialized_ = false;
  std::map<std::string, Account> accounts_;
  std::set<std::string> used_disk_names_;

  mojo::UniqueReceiverSet<ctf::mojom::Folder> folders_;
};

}

int main(int argc, char** argv) {
  base::AtExitManager exit_manager;
  base::CommandLine::Init(argc, argv);
  base::SingleThreadTaskExecutor main_task_executor;

  mojo::core::Configuration config;
  config.is_broker_process = true;
  mojo::core::Init(config);

  base::Thread ipc_thread("mojo-ipc");
  CHECK(ipc_thread.StartWithOptions(
      base::Thread::Options(base::MessagePumpType::IO, 0)));
  mojo::core::ScopedIPCSupport ipc_support(
      ipc_thread.task_runner(),
      mojo::core::ScopedIPCSupport::ShutdownPolicy::CLEAN);

  mojo::PlatformChannel channel;
  base::LaunchOptions options;
  base::CommandLine child_command_line(SandboxeePath());
  channel.PrepareToPassRemoteEndpoint(&options, &child_command_line);

  base::ScopedFD player_in;
  base::ScopedFD player_out;
  if (getenv("CTF_STDIO")) {
    player_in.reset(HANDLE_EINTR(dup(STDIN_FILENO)));
    player_out.reset(HANDLE_EINTR(dup(STDOUT_FILENO)));
    PCHECK(player_in.is_valid() && player_out.is_valid()) << "dup failed";
    options.fds_to_remap.emplace_back(player_in.get(), kPlayerReadFd);
    options.fds_to_remap.emplace_back(player_out.get(), kPlayerWriteFd);
  }

  LOG(INFO) << "[broker] launching sandboxee: "
            << child_command_line.GetCommandLineString();

  base::Process child = base::LaunchProcess(child_command_line, options);
  CHECK(child.IsValid()) << "failed to launch sandboxee";
  channel.RemoteProcessLaunchAttempted();

  mojo::OutgoingInvitation invitation;
  mojo::ScopedMessagePipeHandle pipe = invitation.AttachMessagePipe(kPipeName);

  invitation.set_extra_flags(MOJO_SEND_INVITATION_FLAG_UNTRUSTED_PROCESS);

  mojo::OutgoingInvitation::Send(
      std::move(invitation), child.Handle(), channel.TakeLocalEndpoint(),
      base::BindRepeating([](const std::string& error) {
        LOG(ERROR) << "[broker] mojo process error from sandboxee: " << error;
      }));

  LOG(INFO) << "[broker] invitation sent (untrusted), pipe attached";

  RegistryImpl registry;
  mojo::Receiver<ctf::mojom::Registry> receiver(
      &registry, mojo::PendingReceiver<ctf::mojom::Registry>(std::move(pipe)));

  base::RunLoop run_loop;
  receiver.set_disconnect_handler(base::BindOnce(
      [](base::RunLoop* loop) {
        LOG(INFO) << "[broker] sandboxee disconnected";
        loop->Quit();
      },
      &run_loop));
  run_loop.Run();

  int exit_code = 0;
  child.WaitForExit(&exit_code);
  LOG(INFO) << "[broker] sandboxee exited with " << exit_code;

  const base::FilePath root(StorageRoot());
  if (base::PathExists(root)) {
    base::DeletePathRecursively(root);
  }
  return 0;
}
