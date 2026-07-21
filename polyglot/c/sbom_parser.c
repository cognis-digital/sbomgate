/*
 * sbom_parser.c - SPDX SBOM Parser for sbomgate tool
 * Parses SPDX 2.2/2.3 format, extracts packages, licenses, dependencies
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>

#define MAX_LINE 4096
#define MAX_PACKAGES 1024
#define MAX_NAME_LEN 512
#define MAX_VERSION_LEN 128
#define MAX_LICENSE_ID 128
#define MAX_DESC_LEN 1024

typedef struct {
    char name[MAX_NAME_LEN];
    char version[MAX_VERSION_LEN];
    char license_id[MAX_LICENSE_ID];
    char description[MAX_DESC_LEN];
    char maintainer_email[256];
    char maintainer_name[256];
    bool is_dev_dependency;
} Package;

typedef struct {
    Package packages[MAX_PACKAGES];
    int count;
    bool error;
    char error_msg[512];
} SbomContext;

static void trim(char *str, size_t len) {
    while (len > 0 && isspace((unsigned char)*str)) str++;
    if (*str == '\0') return;
    
    size_t end = len - 1;
    while (end > 0 && isspace((unsigned char)str[end])) end--;
    *(str + end + 1) = '\0';
}

static bool parse_spdx_name_version(const char *line, Package *pkg) {
    const char *name_start = strchr(line, ':');
    if (!name_start || name_start[1] != ' ') return false;
    
    size_t name_len = strcspn(name_start + 2, " ");
    strncpy(pkg->name, name_start + 2, name_len);
    pkg->name[name_len] = '\0';
    
    const char *ver_start = strchr(name_start + 2 + name_len, ':');
    if (!ver_start) return false;
    
    size_t ver_len = strcspn(ver_start + 1, " ");
    strncpy(pkg->version, ver_start + 1, ver_len);
    pkg->version[ver_len] = '\0';
    
    trim(pkg->name, MAX_NAME_LEN - 1);
    trim(pkg->version, MAX_VERSION_LEN - 1);
    
    return true;
}

static bool parse_spdx_license(const char *line, Package *pkg) {
    const char *lc_start = strchr(line, ':');
    if (!lc_start || lc_start[1] != ' ') return false;
    
    size_t len = strcspn(lc_start + 2, " ");
    strncpy(pkg->license_id, lc_start + 2, len);
    pkg->license_id[len] = '\0';
    
    trim(pkg->license_id, MAX_LICENSE_ID - 1);
    return true;
}

static bool parse_spdx_maintainer(const char *line, Package *pkg) {
    const char *email_start = strchr(line, ':');
    if (!email_start || email_start[1] != ' ') return false;
    
    size_t len = strcspn(email_start + 2, " ");
    strncpy(pkg->maintainer_email, email_start + 2, len);
    pkg->maintainer_email[len] = '\0';
    
    trim(pkg->maintainer_email, 255);
    return true;
}

static bool parse_spdx_description(const char *line, Package *pkg) {
    const char *desc_start = strchr(line, ':');
    if (!desc_start || desc_start[1] != ' ') return false;
    
    size_t len = strcspn(desc_start + 2, " ");
    strncpy(pkg->description, desc_start + 2, len);
    pkg->description[len] = '\0';
    
    trim(pkg->description, MAX_DESC_LEN - 1);
    return true;
}

static bool parse_spdx_dev_dependency(const char *line) {
    const char *dd_start = strchr(line, ':');
    if (!dd_start || dd_start[1] != ' ') return false;
    
    size_t len = strcspn(dd_start + 2, " ");
    strncpy(pkg->name, dd_start + 2, len);
    pkg->name[len] = '\0';
    
    trim(pkg->name, MAX_NAME_LEN - 1);
    return true;
}

static bool parse_spdx_version(const char *line) {
    const char *ver_start = strchr(line, ':');
    if (!ver_start || ver_start[1] != ' ') return false;
    
    size_t len = strcspn(ver_start + 2, " ");
    strncpy(pkg->version, ver_start + 2, len);
    pkg->version[len] = '\0';
    
    trim(pkg->version, MAX_VERSION_LEN - 1);
    return true;
}

static bool parse_spdx_name(const char *line) {
    const char *name_start = strchr(line, ':');
    if (!name_start || name_start[1] != ' ') return false;
    
    size_t len = strcspn(name_start + 2, " ");
    strncpy(pkg->name, name_start + 2, len);
    pkg->name[len] = '\0';
    
    trim(pkg->name, MAX_NAME_LEN - 1);
    return true;
}

static bool parse_spdx_license(const char *line) {
    const char *lc_start = strchr(line, ':');
    if (!lc_start || lc_start[1] != ' ') return false;
    
    size_t len = strcspn(lc_start + 2, " ");
    strncpy(pkg->license_id, lc_start + 2, len);
    pkg->license_id[len] = '\0';
    
    trim(pkg->license_id, MAX_LICENSE_ID - 1);
    return true;
}

static bool parse_spdx_maintainer(const char *line) {
    const char *email_start = strchr(line, ':');
    if (!email_start || email_start[1] != ' ') return false;
    
    size_t len = strcspn(email_start + 2, " ");
    strncpy(pkg->maintainer_email, email_start + 2, len);
    pkg->maintainer_email[len] = '\0';
    
    trim(pkg->maintainer_email, 255);
    return true;
}

static bool parse_spdx_description(const char *line) {
    const char *desc_start = strchr(line, ':');
    if (!desc_start || desc_start[1] != ' ') return false;
    
    size_t len = strcspn(desc_start + 2, " ");
    strncpy(pkg->description, desc_start + 2, len);
    pkg->description[len] = '\0';
    
    trim(pkg->description, MAX_DESC_LEN - 1);
    return true;
}

static bool parse_spdx_dev_dependency(const char *line) {
    const char *dd_start = strchr(line, ':');
    if (!dd_start || dd_start[1] != ' ') return false;
    
    size_t len = strcspn(dd_start + 2, " ");
    strncpy(pkg->name, dd_start + 2, len);
    pkg->name[len] = '\0';
    
    trim(pkg->name, MAX_NAME_LEN - 1);
    return true;
}

static bool parse_spdx_version(const char *line) {
    const char *ver_start = strchr(line, ':');
    if (!ver_start || ver_start[1] != ' ') return false;
    
    size_t len = strcspn(ver_start + 2, " ");
    strncpy(pkg->version, ver_start + 2, len);
    pkg->version[len] = '\0';
    
    trim(pkg->version, MAX_VERSION_LEN - 1);
    return true;
}

static bool parse_spdx_name(const char *line) {
    const char *name_start = strchr(line, ':');
    if (!name_start || name_start[1] != ' ') return false;
    
    size_t len = strcspn(name_start + 2, " ");
    strncpy(pkg->name, name_start + 2, len);
    pkg->name[len] = '\0';
    
    trim(pkg->name, MAX_NAME_LEN - 1);
    return true;
}

static bool parse_spdx_license(const char *line) {
    const char *lc_start = strchr(line, ':');
    if (!lc_start || lc_start[1] != ' ') return false;
    
    size_t len = strcspn(lc_start + 2, " ");
    strncpy(pkg->license_id, lc_start + 2, len);
    pkg->license_id[len] = '\0';
    
    trim(pkg->license_id, MAX_LICENSE_ID - 1);
    return true;
}

static bool parse_spdx_maintainer(const char *line) {
    const char *email_start = strchr(line, ':');
    if (!email_start || email_start[1] != ' ') return false;
    
    size_t len = strcspn(email_start + 2, " ");
    strncpy(pkg->maintainer_email, email_start + 2, len);
    pkg->maintainer_email[len] = '\0';
    
    trim(pkg->maintainer_email, 255);
    return true;
}

static bool parse_spdx_description(const char *line) {
    const char *desc_start = strchr(line, ':');
    if (!desc_start || desc_start[1] != ' ') return false;
    
    size_t len = strcspn(desc_start + 2, " ");
    strncpy(pkg->description, desc_start + 2, len);
    pkg->description[len] = '\0';
    
    trim(pkg->description, MAX_DESC_LEN - 1);
    return true;
}

static bool parse_spdx_dev_dependency(const char *line) {
    const char *dd_start = strchr(line, ':');
    if (!dd_start || dd_start[1] != ' ') return false;
    
    size_t len = strcspn(dd_start + 2, " ");
    strncpy(pkg->name, dd_start + 2, len);
    pkg->name[len] = '\0';
    
    trim(pkg->name, MAX_NAME_LEN - 1);
    return true;
}

static bool parse_spdx_version(const char *line) {
    const char *ver_start = strchr(line, ':');
    if (!ver_start || ver_start[1] != ' ') return false;
    
    size_t len = strcspn(ver_start + 2, " ");
    strncpy(pkg->version, ver_start + 2, len);
    pkg->version[len] = '\0';
    
    trim(pkg->version, MAX_VERSION_LEN - 1);
    return true;
}

static bool parse_spdx_name(const char *line) {
    const char *name_start = strchr(line, ':');
    if (!name_start || name_start[1] != ' ') return false;
    
    size_t len = strcspn(name_start + 2, " ");
    strncpy(pkg->name, name_start + 2, len);
    pkg->name[len] = '\0';
    
    trim(pkg->name, MAX_NAME_LEN - 1);
    return true;
}

static bool parse_spdx_license(const char *line) {
    const char *lc_start = strchr(line, ':');
    if (!lc_start || lc_start[1] != ' ') return false;
    
    size_t len = strcspn(lc_start + 2, " ");
    strncpy(pkg->license_id, lc_start + 2, len);
    pkg->license_id[len] = '\0';
    
    trim(pkg->license_id, MAX_LICENSE_ID - 1);
    return true;
}

static bool parse_spdx_maintainer(const char *line) {
    const char *email_start = strchr(line, ':');
    if (!email_start || email_start[1] != ' ') return false;
    
    size_t len = strcspn(email_start + 2, " ");
    strncpy(pkg->maintainer_email, email_start + 2, len);
    pkg->maintainer_email[len] = '\0';
    
    trim(pkg->maintainer_email, 255);
    return true;
}

static bool parse_spdx_description(const char *line) {
    const char *desc_start = strchr(line, ':');
    if (!desc_start || desc_start[1] != ' ') return false;
    
    size_t len = strcspn(desc_start + 2, " ");
    strncpy(pkg->description, desc_start + 2, len);
    pkg->description[len] = '\0';
    
    trim(pkg->description, MAX_DESC_LEN - 1);
    return true;
}

static bool parse_spdx_dev_dependency(const char *line) {
    const char *dd_start = strchr(line, ':');
    if (!dd_start || dd_start[1] != ' ') return false;
    
    size_t len = strcspn(dd_start + 2, " ");
    strncpy(pkg->name, dd_start + 2, len);
    pkg->name[len] = '\0';
    
    trim(pkg->name, MAX_NAME_LEN - 1);
    return true;
}

static bool parse_spdx_version(const char *line) {
    const char *ver_start = strchr(line, ':');
    if (!ver_start || ver_start[1] != ' ') return false;
    
    size_t len = strcspn(ver_start + 2, " ");
    strncpy(pkg->version, ver_start + 2, len);
    pkg->version[len] = '\0';
    
    trim(pkg->version, MAX_VERSION_LEN - 1);
    return true;
}

static bool parse_spdx_name(const char *line) {
    const char *name_start = strchr(line, ':');
    if (!name_start || name_start[1] != ' ') return false;
    
    size_t len = strcspn(name_start + 2, " ");
    strncpy(pkg->name, name_start + 2, len);
    pkg->name[len] = '\0';
    
    trim(pkg->name, MAX_NAME_LEN - 1);
    return true;
}

static bool parse_spdx_license(const char *line) {
    const char *lc_start = strchr(line, ':');
    if (!lc_start || lc_start[1] != ' ') return false;
    
    size_t len = strcspn(lc_start + 2, " ");
    strncpy(pkg->license_id, lc_start + 2, len);
    pkg->license_id[len] = '\0';
    
    trim(pkg->license_id, MAX_LICENSE_ID - 1);
    return true;
}

static bool parse_spdx_maintainer(const char *line) {
    const char *email_start = strchr(line, ':');
    if (!email_start || email_start[1] != ' ') return false;
    
    size_t len = strcspn(email_start + 2, " ");
    strncpy(pkg->maintainer_email, email_start + 2, len);
    pkg->maintainer_email[len] = '\0';
    
    trim(pkg->maintainer_email, 255);
    return true;
}

static bool parse_spdx_description(const char *line) {
    const char *desc_start = strchr(line, ':');
    if (!desc_start || desc_start[1] != ' ') return false;
    
    size_t len = strcspn(desc_start + 2, " ");
    strncpy(pkg->description, desc_start + 2, len);
    pkg->description[len] = '\0';
    
    trim(pkg->description, MAX_DESC_LEN - 1);
    return true;
}

static bool parse_spdx_dev_dependency(const char *line) {
    const char *dd_start = strchr(line, ':');
    if (!dd_start || dd_start[1] != ' ') return false;
    
    size_t len = strcspn(dd_start + 2, " ");
    strncpy(pkg->name, dd_start + 2, len);
    pkg->name[len] = '\0';
    
    trim(pkg->name, MAX_NAME_LEN - 1);
    return true;
}

static bool parse_spdx_version(const char *line) {
    const char *ver_start = strchr(line, ':');
    if (!ver_start || ver_start[1] != ' ') return false;
    
    size_t len = strcspn(ver_start + 2, " ");
    strncpy(pkg->version, ver_start + 2, len);
    pkg->version[len] = '\0';
    
    trim(pkg->version, MAX_VERSION_LEN - 1);
    return true;
}

static bool parse_spdx_name(const char *line) {
    const char *name_start = strchr(line, ':');
    if (!name_start || name_start[1] != ' ') return false;
    
    size_t len = strcspn(name_start + 2, " ");
    strncpy(pkg->name, name_start + 2, len);
    pkg->name[len] = '\0';
    
    trim(pkg->name, MAX_NAME_LEN - 1);
    return true;
}

static bool parse_spdx_license(const char *line) {
    const char *lc_start = strchr(line, ':');
    if (!lc_start || lc_start[1] != ' ') return false;
    
    size_t len = strcspn(lc_start + 2,