// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 */

#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include "dec_test.h"
#include "token_setproc.h"

#define LOG(msg) std::cout << "[dectool][" << __FILE__ << ":" << __LINE__ << "] " << msg << std::endl
#define LOG_ERROR(msg) std::cerr << "[dectool][ERROR][" << __FILE__ << ":" << __LINE__ << "] " << msg << std::endl

struct Command {
    std::string cmd;
    std::string tokenid;
    std::string path;
    std::string dstpath;
    std::string mode;
    std::string userid;
    std::string persist;
    std::string timestamp;
    bool expect;
    bool has_expect;
};

uint64_t stringToUint64(const std::string& str)
{
    try {
        return std::stoull(str, nullptr, 10);
    } catch (const std::exception& e) {
        LOG_ERROR("Failed to convert string to uint64_t: " << str << ", error: " << e.what());
        return 0;
    }
}

int32_t stringToInt32(const std::string& str)
{
    try {
        return std::stoi(str, nullptr, 10);
    } catch (const std::exception& e) {
        LOG_ERROR("Failed to convert string to int32_t: " << str << ", error: " << e.what());
        return 0;
    }
}

uint32_t stringToUint32(const std::string& str)
{
    try {
        return std::stoul(str, nullptr, 0);
    } catch (const std::exception& e) {
        LOG_ERROR("Failed to convert string to uint32_t: " << str << ", error: " << e.what());
        return 0;
    }
}

Command parseCommand(int argc, char* argv[])
{
    Command cmd;
    cmd.expect = false;
    cmd.has_expect = false;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];

        if (arg == "--cmd") {
            cmd.cmd = argv[++i];
        } else if (arg == "--tokenid") {
            cmd.tokenid = argv[++i];
        } else if (arg == "--path") {
            cmd.path = argv[++i];
        } else if (arg == "--dstpath") {
            cmd.dstpath = argv[++i];
        } else if (arg == "--mode") {
            cmd.mode = argv[++i];
        } else if (arg == "--user_id") {
            cmd.userid = argv[++i];
        } else if (arg == "--persist") {
            cmd.persist = argv[++i];
        } else if (arg == "--timestamp") {
            cmd.timestamp = argv[++i];
        } else if (arg == "--expect") {
            cmd.has_expect = true;
            std::string expect = argv[++i];
            cmd.expect = (expect == "true");
        }
    }

    return cmd;
}

int handleRead(const Command& cmd)
{
    SetSelfTokenID(stringToUint64(cmd.tokenid));
    std::ifstream file(cmd.path.c_str(), std::ios::binary);
    if (!file.is_open()) {
        LOG_ERROR("Failed to open file for reading: " << cmd.path << ", errno: " << errno << " - " << strerror(errno));
        return -1;
    }

    std::string content((std::istreambuf_iterator<char>(file)),
                        std::istreambuf_iterator<char>());
    file.close();

    LOG("Successfully read file: " << cmd.path);
    return 0;
}

int handleWrite(const Command& cmd)
{
    SetSelfTokenID(stringToUint64(cmd.tokenid));
    std::ofstream file(cmd.path.c_str(), std::ios::binary | std::ios::app);
    if (!file.is_open()) {
        LOG_ERROR("Failed to open file for writing: " << cmd.path << ", errno: " << errno << " - " << strerror(errno));
        return -1;
    }

    file << "Test data written by dectool\n";
    file.close();

    LOG("Successfully wrote to file: " << cmd.path);
    return 0;
}

int handleCreate(const Command& cmd)
{
    SetSelfTokenID(stringToUint64(cmd.tokenid));
    std::ofstream file(cmd.path.c_str());
    if (!file.is_open()) {
        LOG_ERROR("Failed to create file: " << cmd.path << ", errno: " << errno << " - " << strerror(errno));
        return -1;
    }

    file.close();
    LOG("Successfully created file: " << cmd.path);
    return 0;
}

int handleReaddir(const Command& cmd)
{
    SetSelfTokenID(stringToUint64(cmd.tokenid));
    DIR* dir = opendir(cmd.path.c_str());
    if (!dir) {
        LOG_ERROR("Failed to open directory: " << cmd.path << ", errno: " << errno << " - " << strerror(errno));
        return -1;
    }

    struct dirent* entry;
    int count = 0;
    while ((entry = readdir(dir)) != nullptr) {
        count++;
    }

    closedir(dir);
    LOG("Successfully read directory: " << cmd.path << ", found " << count << " entries");
    return 0;
}

int handleMkdir(const Command& cmd)
{
    SetSelfTokenID(stringToUint64(cmd.tokenid));
    std::string path = cmd.path;
    if(path.empty()) {
        printf("path is empty\n");
        return -1;
    }

    const char lastChar = path.back();
    if(lastChar != '\\' && lastChar != '/') {
        path.append("/");
    }
    printf("start mkdir %s\n", path.c_str());
    int len = path.length();
    char tmpDirPath[256] = { 0 };
    for (int i = 0; i < len; i++) {
        tmpDirPath[i] = path[i];
        if (tmpDirPath[i] == '\\' || tmpDirPath[i] == '/') {
            printf("tmpDirPath:%s\n", tmpDirPath);
            if (access(tmpDirPath, 0) == -1) {
                printf("tmpDirPath:%s not exist\n", tmpDirPath);
                int ret = mkdir(tmpDirPath, S_IRWXU);
                if (ret == -1) {
                    printf("mkdir failed %s\n", strerror(errno));
                    return -1;
                }
            } else {
                printf("tmpDirPath:%s exists\n", tmpDirPath);
            }
        }
    }
    printf("mkdir success path:%s\n", path.c_str());
    return 0;
}

int handleRemove(const Command& cmd)
{
    SetSelfTokenID(stringToUint64(cmd.tokenid));
    if (std::remove(cmd.path.c_str()) == 0) {
        LOG("Successfully removed file: " << cmd.path);
        return 0;
    }

    LOG_ERROR("Failed to remove file: " << cmd.path << ", errno: " << errno << " - " << strerror(errno));
    return -1;
}

std::string GetFileDir(const std::string &fileName)
{
    size_t lastSlashPos = fileName.find_last_of("/\\");

    if (lastSlashPos == std::string::npos) {
        printf("cant find file:%s\n", fileName.c_str());
        return "";
    }

    std::string fileDir = fileName.substr(0, lastSlashPos);
    return fileDir;
}


int handleCopy(const Command& cmd)
{
    SetSelfTokenID(stringToUint64(cmd.tokenid));
    std::string srcPath = cmd.path;
    std::string dstPath = cmd.dstpath;
    printf("copy %s to %s \n", srcPath.c_str(), dstPath.c_str());
    std::ifstream in(srcPath, std::ios::binary);
    std::ofstream out(dstPath, std::ios::binary);

    if (!in) {
        std::cerr << "open fail" << std::endl;
        return 1;
    }

    if (!out) {
        std::cerr << "open fail" << std::endl;
        return 1;
    }

    out << in.rdbuf();

    in.close();
    out.close();

    std::cout << "copy success" << std::endl;

    return 0;
}

int handleRename(const Command& cmd)
{
    SetSelfTokenID(stringToUint64(cmd.tokenid));
    std::string fileName = cmd.path;
    std::__fs::filesystem::path filePath = cmd.path;
    std::string newName = GetFileDir(cmd.path);
    newName.append("/new");
    newName.append(filePath.filename());
    printf("fileName:%s newName:%s\n", fileName.c_str(), newName.c_str());
    int ret = rename(fileName.c_str(), newName.c_str());
    if (ret != 0) {
        printf("rename failed err:%s\n", strerror(errno));
        return -1;
    }

    ret = rename(newName.c_str(), fileName.c_str());
    if (ret != 0) {
        printf("rename back failed err:%s\n", strerror(errno));
        return -1;
    }
    return 0;

    LOG_ERROR("Failed to rename " << cmd.path << " to " << cmd.dstpath << ", errno: " << errno << " - " << strerror(errno));
    return -1;
}

int handleRename2(const Command& cmd)
{
    SetSelfTokenID(stringToUint64(cmd.tokenid));
    if (std::rename(cmd.path.c_str(), cmd.dstpath.c_str()) == 0) {
        LOG("Successfully renamed " << cmd.path << " to " << cmd.dstpath);
        return 0;
    }

    LOG_ERROR("Failed to rename " << cmd.path << " to " << cmd.dstpath << ", errno: " << errno << " - " << strerror(errno));
    return -1;
}

int handleAccess(const Command& cmd)
{
    SetSelfTokenID(stringToUint64(cmd.tokenid));
    int mode = 0;
    if (!cmd.mode.empty()) {
        try {
            mode = std::stoi(cmd.mode);
        } catch (const std::exception& e) {
            LOG_ERROR("Invalid mode value: " << cmd.mode << ", error: " << e.what());
            return -1;
        }
    }

    int checkMode = 0;
    switch (mode) {
        case 0: checkMode = F_OK; break;
        case 1: checkMode = R_OK; break;
        case 2: checkMode = W_OK; break;
        case 3: checkMode = R_OK | W_OK; break;
        default:
            LOG_ERROR("Invalid mode specified: " << mode);
            return -1;
    }

    if (access(cmd.path.c_str(), checkMode) == 0) {
        LOG("Access check passed for " << cmd.path << " with mode " << mode);
        return 0;
    }

    LOG_ERROR("Access check failed for " << cmd.path << " with mode " << mode << ", errno: " << errno << " - " << strerror(errno));
    return -1;
}

int handleSet(const Command& cmd)
{
    if (cmd.tokenid.empty()) {
        LOG_ERROR("tokenid is required for set command");
        return -1;
    }

    if (cmd.path.empty()) {
        LOG_ERROR("path is required for set command");
        return -1;
    }

    if (cmd.mode.empty()) {
        LOG_ERROR("mode is required for set command");
        return -1;
    }

    uint64_t tokenid = stringToUint64(cmd.tokenid);

    uint32_t mode = stringToUint32(cmd.mode);

    bool persistFlag = false;
    if (!cmd.persist.empty()) {
        persistFlag = (cmd.persist == "true");
    }

    uint64_t timestamp = 0;
    if (!cmd.timestamp.empty()) {
        timestamp = stringToUint64(cmd.timestamp);
    }

    int32_t userId = 0;
    if (!cmd.userid.empty()) {
        userId = stringToInt32(cmd.userid);
    }

    LOG("Calling SetPath: tokenid=" << tokenid << ", path=" << cmd.path 
        << ", mode=" << mode << ", persistFlag=" << persistFlag 
        << ", timestamp=" << timestamp << ", userId=" << userId);

    int result = SetPath(tokenid, cmd.path, mode, persistFlag, timestamp, userId);
    LOG("SetPath returned: " << result);

    return result;
}

int handleConstraint(const Command& cmd)
{
    if (cmd.path.empty()) {
        LOG_ERROR("path is required for constraint command");
        return -1;
    }

    LOG("Calling ConstraintPath: path=" << cmd.path);
    int result = ConstraintPath(cmd.path);
    LOG("ConstraintPath returned: " << result);

    return result;
}

int handleCheck(const Command& cmd)
{
    if (cmd.tokenid.empty()) {
        LOG_ERROR("tokenid is required for check command");
        return -1;
    }

    if (cmd.path.empty()) {
        LOG_ERROR("path is required for check command");
        return -1;
    }

    uint64_t tokenid = stringToUint64(cmd.tokenid);

    uint32_t mode = 0;
    if (!cmd.mode.empty()) {
        mode = stringToUint32(cmd.mode);
    } else {
        LOG_ERROR("mode is required for check command");
        return -1;
    }

    LOG("Calling CheckPath: tokenid=" << tokenid << ", path=" << cmd.path << ", mode=" << mode);
    int result = CheckPath(tokenid, cmd.path, mode);
    LOG("CheckPath returned: " << result);

    return result;
}

int handleQuery(const Command& cmd)
{
    if (cmd.tokenid.empty()) {
        LOG_ERROR("tokenid is required for query command");
        return -1;
    }

    if (cmd.path.empty()) {
        LOG_ERROR("path is required for query command");
        return -1;
    }

    uint64_t tokenid = stringToUint64(cmd.tokenid);

    uint32_t mode = 0;
    if (!cmd.mode.empty()) {
        mode = stringToUint32(cmd.mode);
    } else {
        LOG_ERROR("mode is required for query command");
        return -1;
    }

    LOG("Calling QueryPath: tokenid=" << tokenid << ", path=" << cmd.path << ", mode=" << mode);
    int result = QueryPath(tokenid, cmd.path, mode);
    LOG("QueryPath returned: " << result);

    return result;
}

int handleDelete(const Command& cmd)
{
    if (cmd.tokenid.empty()) {
        LOG_ERROR("tokenid is required for delete command");
        return -1;
    }

    if (cmd.path.empty()) {
        LOG_ERROR("path is required for delete command");
        return -1;
    }

    uint64_t tokenid = stringToUint64(cmd.tokenid);

    uint64_t timestamp = 0;
    if (!cmd.timestamp.empty()) {
        timestamp = stringToUint64(cmd.timestamp);
    }

    LOG("Calling DeletePath: tokenid=" << tokenid << ", path=" << cmd.path << ", timestamp=" << timestamp);
    int result = DeletePath(tokenid, cmd.path, timestamp);
    LOG("DeletePath returned: " << result);

    return result;
}

int handleDeleteByUser(const Command& cmd)
{
    if (cmd.userid.empty()) {
        LOG_ERROR("userid is required for delete_by_user command");
        return -1;
    }

    if (cmd.path.empty()) {
        LOG_ERROR("path is required for delete_by_user command");
        return -1;
    }

    int32_t userId = stringToInt32(cmd.userid);

    LOG("Calling DeletePathByUser: user_id=" << userId << ", path=" << cmd.path);
    int result = DeletePathByUser(userId, cmd.path);
    LOG("DeletePathByUser returned: " << result);

    return result;
}

int handleDestroy(const Command& cmd)
{
    if (cmd.tokenid.empty()) {
        LOG_ERROR("tokenid is required for destroy command");
        return -1;
    }

    uint64_t tokenid = stringToUint64(cmd.tokenid);

    uint64_t timestamp = 0;
    if (!cmd.timestamp.empty()) {
        timestamp = stringToUint64(cmd.timestamp);
    }

    LOG("Calling DestroyByTokenid: tokenid=" << tokenid << ", timestamp=" << timestamp);
    int result = DestroyByTokenid(tokenid, timestamp);
    LOG("DestroyByTokenid returned: " << result);

    return result;
}

int handleForcedPrefix(const Command& cmd)
{
    if (cmd.path.empty()) {
        LOG_ERROR("path is required for forced_prefix command");
        return -1;
    }

    LOG("Calling SetPrefix: path=" << cmd.path);
    int result = SetPrefix(cmd.path);
    LOG("SetPrefix returned: " << result);

    return result;
}

int main(int argc, char* argv[])
{
    LOG("Starting dectool with " << argc << " arguments");

    if (argc < 2) {
        LOG_ERROR("Usage: " << argv[0] << " --cmd <command> [options]");
        return -1;
    }

    Command cmd = parseCommand(argc, argv);
    LOG("Parsed command: cmd=" << cmd.cmd << ", path=" << cmd.path << ", has_expect=" << cmd.has_expect << ", expect=" << cmd.expect);

    int result = -1;

    LOG("tokenid=" << cmd.tokenid);

    uint64_t tokenid = stringToUint64(cmd.tokenid);

    OpenDevDec();

    if (cmd.cmd == "read") {
        result = handleRead(cmd);
    } else if (cmd.cmd == "write") {
        result = handleWrite(cmd);
    } else if (cmd.cmd == "create") {
        result = handleCreate(cmd);
    } else if (cmd.cmd == "readdir") {
        result = handleReaddir(cmd);
    } else if (cmd.cmd == "mkdir") {
        result = handleMkdir(cmd);
    } else if (cmd.cmd == "remove") {
        result = handleRemove(cmd);
    } else if (cmd.cmd == "rename") {
        result = handleRename(cmd);
    } else if (cmd.cmd == "rename2") {
        if (cmd.dstpath.empty()) {
            LOG_ERROR("dstpath is required for rename command");
            return -1;
        }
        result = handleRename2(cmd);
    } else if (cmd.cmd == "copy") {
        result = handleCopy(cmd);
    }  else if (cmd.cmd == "access") {
        result = handleAccess(cmd);
    } else if (cmd.cmd == "set") {
        result = handleSet(cmd);
    } else if (cmd.cmd == "constraint") {
        result = handleConstraint(cmd);
    } else if (cmd.cmd == "check") {
        result = handleCheck(cmd);
    } else if (cmd.cmd == "query") {
        result = handleQuery(cmd);
    } else if (cmd.cmd == "delete") {
        result = handleDelete(cmd);
    } else if (cmd.cmd == "delete_by_user") {
        result = handleDeleteByUser(cmd);
    } else if (cmd.cmd == "destroy") {
        result = handleDestroy(cmd);
    } else if (cmd.cmd == "forced_prefix") {
        result = handleForcedPrefix(cmd);
    } else {
        LOG_ERROR("Unknown command: " << cmd.cmd);
        return -1;
    }

    LOG("Command '" << cmd.cmd << "' executed with result: " << result);

    if (!cmd.has_expect) {
        LOG("No expect parameter specified, returning 0");
        return 0;
    } else {
        if (cmd.expect) {
            if (result == 0) {
                LOG("Command succeeded as expected (expect=true, result=0), returning 0");
                return 0;
            } else {
                LOG_ERROR("Command failed unexpectedly (expect=true, result=" << result << "), returning -1");
                return -1;
            }
        } else {
            if (result != 0) {
                LOG("Command failed as expected (expect=false, result=" << result << "), returning 0");
                return 0;
            } else {
                LOG_ERROR("Command succeeded unexpectedly (expect=false, result=0), returning -1");
                return -1;
            }
        }
    }
}