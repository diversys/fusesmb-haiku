/*
 * SMB for FUSE
 *
 * Mount complete "Network Neighbourhood"
 *
 * Copyright (C) 2006 Vincent Wagelaar
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include "config.h"

#include <fs_info.h>
#define HAS_FUSE_HAIKU_EXTENSIONS

#include "haiku/support.h"

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/param.h>
#include <sys/statvfs.h>
#include <sys/time.h>
#include <pthread.h>
#include <libsmbclient.h>
#include <time.h>
#include "debug.h"
#include "hash.h"
#include "smbctx.h"

#define MY_MAXPATHLEN (MAXPATHLEN + 256)

#define FILE_HANDLE_NEEDS_AUTHENTICATION 0x7
	/* fusesmb uses the file handle to store pointers, so this is just
	   a unique value which will never be a valid pointer (and also not
	   NULL) */

/* Mutex for locking the Samba context */

/* To prevent deadlock, locking order should be:

[rwd]ctx_mutex -> cfg_mutex -> opts_mutex
[rwd]ctx_mutex -> opts_mutex
*/

static pthread_mutex_t ctx_mutex = PTHREAD_MUTEX_INITIALIZER;
static SMBCCTX *ctx, *rwd_ctx;
pthread_t cleanup_thread;


struct fusesmb_opt {
    int global_showhiddenshares;
    int global_interval;
    int global_timeout;
    char *global_username;
    char *global_password;
};
/* Read settings from fusesmb.conf and or set default value */
config_t cfg;
pthread_mutex_t cfg_mutex = PTHREAD_MUTEX_INITIALIZER;
struct fusesmb_opt opts;
pthread_mutex_t opts_mutex = PTHREAD_MUTEX_INITIALIZER;
char fusesmb_scan_bin[MAXPATHLEN];

static const char kMimeTypeAttributeName[] = "BEOS:TYPE";

static void options_read(config_t *cfg, struct fusesmb_opt *opt)
{
    if (-1 == config_read_bool(cfg, "global", "showhiddenshares", &(opt->global_showhiddenshares)))
        opt->global_showhiddenshares = 1;
    if (-1 == config_read_int(cfg, "global", "timeout", &(opt->global_timeout)))
        opt->global_timeout = 10;

    /* Timeout less then 2 seconds is not really useful */
    if(opt->global_timeout <= 2)
        opt->global_timeout = 2;

    if (-1 == config_read_int(cfg, "global", "interval", &(opt->global_interval)))
        opt->global_interval = 15;
    if (opt->global_interval <= 0)
        opt->global_interval = 0;

    if (-1 == config_read_string(cfg, "global", "username", &(opt->global_username)))
        opt->global_username = NULL;
    if (-1 == config_read_string(cfg, "global", "password", &(opt->global_password)))
        opt->global_password = NULL;
}

static void options_free(struct fusesmb_opt *opt)
{
    if (NULL != opt->global_username)
        free(opt->global_password);
    if (NULL != opt->global_password)
        free(opt->global_username);
}

static SMBCFILE*
get_smbcfile(struct fuse_file_info* file_info)
{
	return (SMBCFILE*)((uintptr_t)file_info->fh);
}


/*
 * Thread for cleaning up connections to hosts, current interval of
 * 15 seconds looks reasonable
 */
static void *smb_purge_thread(void *data)
{
    (void)data;
    while (1)
    {

        pthread_mutex_lock(&ctx_mutex);
        ctx->callbacks.purge_cached_fn(ctx);
        rwd_ctx->callbacks.purge_cached_fn(rwd_ctx);
        pthread_mutex_unlock(&ctx_mutex);

        char cachefile[1024];
        get_path_in_settings_dir(&cachefile[0], sizeof(cachefile),
            "fusesmb.cache");
        struct stat st;
        memset(&st, 0, sizeof(struct stat));

        if(opts.global_interval > 0)
        {
            if (-1 == stat(cachefile, &st))
            {
                if (errno == ENOENT)
                {
                    system(fusesmb_scan_bin);
                }
            }
            else if (time(NULL) - st.st_mtime > opts.global_interval * 60)
            {
                system(fusesmb_scan_bin);
            }
        }


        /* Look if any changes have been made to the configfile */
        int changed;
        pthread_mutex_lock(&cfg_mutex);
        if (0 == (changed = config_reload_ifneeded(&cfg)))
        {
            /* Lookout for deadlocks !!!! (order of setting locks within locks) */
            pthread_mutex_lock(&opts_mutex);
            options_free(&opts);
            options_read(&cfg, &opts);
            pthread_mutex_unlock(&opts_mutex);
        }
        pthread_mutex_unlock(&cfg_mutex);

        /* Prevent unnecessary locks within locks */
        if (changed == 0)
        {
            pthread_mutex_lock(&ctx_mutex);
            ctx->timeout = opts.global_timeout * 1000;
            rwd_ctx->timeout = opts.global_timeout * 1000;
            pthread_mutex_unlock(&ctx_mutex);
        }


        sleep(15);
    }
    return NULL;
}

static const char *stripworkgroup(const char *file)
{
    unsigned int i = 0, ret = 0, goodpos = 0, file_len = strlen(file);

    for (i = 0; i < file_len; i++)
    {
        if (ret == 2)
        {
            goodpos--;
            break;
        }
        if (file[i] == '/')
            ret++;
        goodpos++;
    }
    if (ret == 1)
        return file;
    else
        return &file[goodpos];
}

static unsigned int slashcount(const char *file)
{
    unsigned int i = 0, count = 0, file_len = strlen(file);

    for (i = 0; i < file_len; i++)
    {
        if (file[i] == '/')
            count++;
    }
    return count;
}

static int fusesmb_getattr(const char *path, struct stat *stbuf)
{
    char smb_path[MY_MAXPATHLEN] = "smb:/", buf[MY_MAXPATHLEN], cache_file[1024];
    int path_exists = 0;
    FILE *fp;
    struct stat cache;
    memset(stbuf, 0, sizeof(struct stat));

    /* Check the cache for valid workgroup, hosts and shares */
    if (slashcount(path) <= 3)
    {
        get_path_in_settings_dir(&cache_file[0], sizeof(cache_file),
            "fusesmb.cache");

        if (strlen(path) == 1 && path[0] == '/')
            path_exists = 1;
        else
        {
            fp = fopen(cache_file, "r");
            if (!fp)
                return -ENOENT;

            while (!feof(fp))
            {
                fgets(buf, MY_MAXPATHLEN, fp);
                if (strncmp(buf, path, strlen(path)) == 0 &&
                    (buf[strlen(path)] == '/' || buf[strlen(path)] == '\n'))
                {
                    path_exists = 1;
                    break;
                }
            }
            fclose(fp);
        }
        if (path_exists != 1)
            return -ENOENT;

        memset(&cache, 0, sizeof(cache));
        stat(cache_file, &cache);
        memset(stbuf, 0, sizeof(*stbuf));
        stbuf->st_mode  = S_IFDIR | 0755;
        stbuf->st_nlink = 3;
        stbuf->st_size  = 4096;
        stbuf->st_uid   = cache.st_uid;
        stbuf->st_gid   = cache.st_gid;
        stbuf->st_ctime = cache.st_ctime;
        stbuf->st_mtime = cache.st_mtime;
        stbuf->st_atime = cache.st_atime;
        return 0;

    }
    /* We're within a share here  */
    else
    {
        strcat(smb_path, stripworkgroup(path));
        pthread_mutex_lock(&ctx_mutex);
        if (ctx->stat(ctx, smb_path, stbuf) < 0)
        {
            pthread_mutex_unlock(&ctx_mutex);
            return -errno;
        }

        stbuf->st_mode &= ~(S_IXUSR | S_IXGRP | S_IXOTH);
        	// remove executable bits (Samba uses them for certain DOS file
        	// attributes)

        pthread_mutex_unlock(&ctx_mutex);
        return 0;

    }
}

static int fusesmb_opendir(const char *path, struct fuse_file_info *fi)
{
    if (slashcount(path) <= 2)
        return 0;
    SMBCFILE *dir;
    char smb_path[MY_MAXPATHLEN] = "smb:/";
    strcat(smb_path, stripworkgroup(path));
    pthread_mutex_lock(&ctx_mutex);
    dir = ctx->opendir(ctx, smb_path);
    if (dir == NULL)
    {
        if (errno != EACCES) {
            pthread_mutex_unlock(&ctx_mutex);
            return -errno;
        } else {
            fi->fh = FILE_HANDLE_NEEDS_AUTHENTICATION;
            pthread_mutex_unlock(&ctx_mutex);
            return 0;
        }
    }
    fi->fh = (unsigned long)dir;
    pthread_mutex_unlock(&ctx_mutex);
    return 0;
}

static int fusesmb_readdir(const char *path, void *h, fuse_fill_dir_t filler,
                       off_t offset, struct fuse_file_info *fi)
{
    (void)offset;
    struct smbc_dirent *pdirent;
    char buf[MY_MAXPATHLEN],
         last_dir_entry[MY_MAXPATHLEN] = "",
         cache_file[1024];
    FILE *fp;
    char *dir_entry;
    struct stat st;
    memset(&st, 0, sizeof(st));
    int dircount = 0;

    /*
       Check the cache file for workgroups/hosts and shares that are currently online
       Cases handled here are:
       / ,
       /WORKGROUP and
       /WORKGROUP/COMPUTER
     */
    if (slashcount(path) <= 2)
    {
        /* Listing Workgroups */
        get_path_in_settings_dir(&cache_file[0], sizeof(cache_file),
            "fusesmb.cache");
        fp = fopen(cache_file, "r");
        if (!fp)
            return -ENOENT;
        while (!feof(fp))
        {
            if (NULL == fgets(buf, sizeof(buf), fp))
                continue;

            if (strncmp(buf, path, strlen(path)) == 0 &&
                (strlen(buf) > strlen(path)))
            {
                /* Note: strtok is safe because the static buffer is is not reused */
                if (buf[strlen(path)] == '/' || strlen(path) == 1)
                {
                    /* Path is workgroup or server */
                    if (strlen(path) > 1)
                    {
                        dir_entry = strtok(&buf[strlen(path) + 1], "/");
                        /* Look if share is a hidden share, dir_entry still contains '\n' */
                        if (slashcount(path) == 2)
                        {
                            if (dir_entry[strlen(dir_entry)-2] == '$')
                            {
                                int showhidden = 0;
                                pthread_mutex_lock(&cfg_mutex);
                                if (0 == config_read_bool(&cfg, stripworkgroup(path), "showhiddenshares", &showhidden))
                                {
                                    pthread_mutex_unlock(&cfg_mutex);
                                    if (showhidden == 1)
                                        continue;
                                }
                                pthread_mutex_unlock(&cfg_mutex);

                                pthread_mutex_lock(&opts_mutex);
                                if (opts.global_showhiddenshares == 0)
                                {
                                    pthread_mutex_unlock(&opts_mutex);
                                    continue;
                                }
                                pthread_mutex_unlock(&opts_mutex);
                            }
                        }
                    }
                    /* Path is root */
                    else
                    {
                        dir_entry = strtok(buf, "/");
                    }
                    /* Only unique workgroups or servers */
                    if (strcmp(last_dir_entry, dir_entry) == 0)
                        continue;

                    st.st_mode = S_IFDIR;
                    filler(h, strtok(dir_entry, "\n"), &st, 0);
                    dircount++;
                    strncpy(last_dir_entry, dir_entry, MY_MAXPATHLEN);
                }
            }
        }
        fclose(fp);

        if (dircount == 0)
            return -ENOENT;

        /* The workgroup / host and share lists don't have . and .. , so putting them in */
        st.st_mode = S_IFDIR;
        filler(h, ".", &st, 0);
        filler(h, "..", &st, 0);
        return 0;
    }
    /* Listing contents of a share */
    else
    {
        while (fi->fh == FILE_HANDLE_NEEDS_AUTHENTICATION) {
            int result = show_authentication_request(path);
            if (result != 0) {
                // User cancelled
                return -EACCES;
            }
            int status = fusesmb_opendir(path, fi);
            if (status != 0)
                return status;
        }

        pthread_mutex_lock(&ctx_mutex);
        while (NULL != (pdirent = ctx->readdir(ctx, get_smbcfile(fi))))
        {
            if (pdirent->smbc_type == SMBC_DIR)
            {
                st.st_mode = S_IFDIR;
                filler(h, pdirent->name, &st, 0);
            }
            if (pdirent->smbc_type == SMBC_FILE)
            {
                st.st_mode = S_IFREG;
                filler(h, pdirent->name, &st, 0);
            }
        }
        pthread_mutex_unlock(&ctx_mutex);
    }
    return 0;
}

static int fusesmb_releasedir(const char *path, struct fuse_file_info *fi)
{
    (void) path;
    if (slashcount(path) <= 2)
        return 0;

    pthread_mutex_lock(&ctx_mutex);
    ctx->closedir(ctx, get_smbcfile(fi));
    pthread_mutex_unlock(&ctx_mutex);
    return 0;
}

static int fusesmb_open(const char *path, struct fuse_file_info *fi)
{
    SMBCFILE *file;
    char smb_path[MY_MAXPATHLEN] = "smb:/";

    if (slashcount(path) <= 3)
        return 0;

    /* Not sure what this code is doing */
    //if((flags & 3) != O_RDONLY)
    //    return -ENOENT;
    strcat(smb_path, stripworkgroup(path));

    pthread_mutex_lock(&ctx_mutex);
    file = rwd_ctx->open(rwd_ctx, smb_path, fi->flags, 0);

    if (file == NULL)
    {
        if (errno == EISDIR) {
            strlcat(smb_path, "/", MY_MAXPATHLEN);
            file = smbc_getFunctionOpen(rwd_ctx)(rwd_ctx, smb_path, fi->flags, 0);
        }
        if (file == NULL) {
            pthread_mutex_unlock(&ctx_mutex);
            return -errno;
        }
    }

    fi->fh = (unsigned long)file;
    pthread_mutex_unlock(&ctx_mutex);
    return 0;
}

static int fusesmb_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    SMBCFILE *file;
    char smb_path[MY_MAXPATHLEN] = "smb:/";

    //printf("%i\n", offset);
    //fflush(stdout);

    strcat(smb_path, stripworkgroup(path));

    int tries = 0;              //For number of retries before failing
    ssize_t ssize;              //Returned by ctx->read

    pthread_mutex_lock(&ctx_mutex);
    /* Ugly goto but it works ;) But IMHO easiest solution for error handling here */
    goto seek;
  reopen:
    if ((file = rwd_ctx->open(rwd_ctx, smb_path, fi->flags, 0)) == NULL)
    {
        /* Trying to reopen when out of memory */
        if (errno == ENOMEM)
        {
            tries++;
            if (tries > 4)
            {
                pthread_mutex_unlock(&ctx_mutex);
                return -errno;
            }
            goto reopen;
        }
        /* Other errors from docs cannot be recovered from so returning the error */
        else
        {
            pthread_mutex_unlock(&ctx_mutex);
            return -errno;
        }
    }
    fi->fh = (unsigned long)file;
  seek:

    if (rwd_ctx->lseek(rwd_ctx, get_smbcfile(fi), offset, SEEK_SET) == (off_t) - 1)
    {
        /* Bad file descriptor try to reopen */
        if (errno == EBADF)
        {
            goto reopen;
        }
        else
        {
            //SMB Init failed
            pthread_mutex_unlock(&ctx_mutex);
            return -errno;
        }
    }
    if ((ssize = rwd_ctx->read(rwd_ctx, get_smbcfile(fi), buf, size)) < 0)
    {
        /* Bad file descriptor try to reopen */
        if (errno == EBADF)
        {
            goto reopen;
        }
        /* Tried opening a directory / or smb_init failed */
        else
        {
            pthread_mutex_unlock(&ctx_mutex);
            return -errno;
        }
    }
    pthread_mutex_unlock(&ctx_mutex);
    return (size_t) ssize;
}

static int fusesmb_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    SMBCFILE *file;
    char smb_path[MY_MAXPATHLEN] = "smb:/";

    strcat(smb_path, stripworkgroup(path));

    int tries = 0;              //For number of retries before failing
    ssize_t ssize;              //Returned by ctx->read

    pthread_mutex_lock(&ctx_mutex);
    /* Ugly goto but it works ;) But IMHO easiest solution for error handling here */
    goto seek;
  reopen:
    if (NULL == (file = rwd_ctx->open(rwd_ctx, smb_path, fi->flags, 0)))
    {
        /* Trying to reopen when out of memory */
        if (errno == ENOMEM)
        {
            tries++;
            if (tries > 4)
            {
                pthread_mutex_unlock(&ctx_mutex);
                return -errno;
            }
            goto reopen;
        }
        /* Other errors from docs cannot be recovered from so returning the error */
        pthread_mutex_unlock(&ctx_mutex);
        return -errno;

    }
    fi->fh = (unsigned long)file;
  seek:

    if (rwd_ctx->lseek(rwd_ctx, get_smbcfile(fi), offset, SEEK_SET) == (off_t) - 1)
    {
        /* Bad file descriptor try to reopen */
        if (errno == EBADF)
        {
            goto reopen;
        }
        else
        {
            //SMB Init failed
            pthread_mutex_unlock(&ctx_mutex);
            return -errno;
        }
    }
    if ((ssize = rwd_ctx->write(rwd_ctx, get_smbcfile(fi), (void *) buf, size)) < 0)
    {
        /* Bad file descriptor try to reopen */
        if (errno == EBADF)
        {
            goto reopen;
        }
        /* Tried opening a directory / or smb_init failed */
        else
        {
            pthread_mutex_unlock(&ctx_mutex);
            return -errno;
        }
    }
    pthread_mutex_unlock(&ctx_mutex);
    return (size_t) ssize;
}

static int fusesmb_release(const char *path, struct fuse_file_info *fi)
{
    (void)path;
    pthread_mutex_lock(&ctx_mutex);
#ifdef HAVE_LIBSMBCLIENT_CLOSE_FN
    rwd_ctx->close_fn(rwd_ctx, get_smbcfile(fi));
#else
    rwd_ctx->close(rwd_ctx, get_smbcfile(fi));
#endif
    pthread_mutex_unlock(&ctx_mutex);
    return 0;

}

static int fusesmb_mknod(const char *path, mode_t mode,
                     __attribute__ ((unused)) dev_t rdev)
{
    char smb_path[MY_MAXPATHLEN] = "smb:/";
    SMBCFILE *file;

    /* FIXME:
       Check which rdevs are supported, currently only a file
       is created
     */
    //if (rdev != S_IFREG)
    //  return -EACCES;
    if (slashcount(path) <= 3)
        return -EACCES;

    strcat(smb_path, stripworkgroup(path));
    pthread_mutex_lock(&ctx_mutex);
    if ((file = ctx->creat(ctx, smb_path, mode)) == NULL)
    {
        pthread_mutex_unlock(&ctx_mutex);
        return -errno;
    }
#ifdef HAVE_LIBSMBCLIENT_CLOSE_FN
    ctx->close_fn(ctx, file);
#else
    ctx->close(ctx, file);
#endif

    pthread_mutex_unlock(&ctx_mutex);

    return 0;
}

static int fusesmb_create(const char *path, mode_t mode, struct fuse_file_info* fi)
{
	char smb_path[MY_MAXPATHLEN] = "smb:/";
	SMBCFILE *file;

	if (slashcount(path) <= 3)
		return -EACCES;

	strcat(smb_path, stripworkgroup(path));
	pthread_mutex_lock(&ctx_mutex);
	if ((file = smbc_getFunctionCreat(rwd_ctx)(rwd_ctx, smb_path, mode)) == NULL)
	{
		pthread_mutex_unlock(&ctx_mutex);
		return -errno;
	}

	fi->fh = (unsigned long) file;

	pthread_mutex_unlock(&ctx_mutex);

	return 0;
}

static int fusesmb_statfs(const char *path, struct statvfs *fst)
{
    /* Returning stat of local filesystem, call is too expensive */
    (void)path;
    memset(fst, 0, sizeof(struct statvfs));
    if (statvfs("/", fst) != 0)
        return -errno;
    return 0;
}

static int fusesmb_unlink(const char *file)
{
    char smb_path[MY_MAXPATHLEN] = "smb:/";

    if (slashcount(file) <= 3)
        return -EACCES;

    strcat(smb_path, stripworkgroup(file));
    pthread_mutex_lock(&ctx_mutex);
    if (ctx->unlink(ctx, smb_path) < 0)
    {
        pthread_mutex_unlock(&ctx_mutex);
        return -errno;
    }
    pthread_mutex_unlock(&ctx_mutex);
    return 0;
}

static int fusesmb_rmdir(const char *path)
{
    char smb_path[MY_MAXPATHLEN] = "smb:/";

    if (slashcount(path) <= 3)
        return -EACCES;

    strcat(smb_path, stripworkgroup(path));
    pthread_mutex_lock(&ctx_mutex);

    if (ctx->rmdir(ctx, smb_path) < 0)
    {
        pthread_mutex_unlock(&ctx_mutex);
        return -errno;
    }
    pthread_mutex_unlock(&ctx_mutex);
    return 0;
}

static int fusesmb_mkdir(const char *path, mode_t mode)
{
    char smb_path[MY_MAXPATHLEN] = "smb:/";

    if (slashcount(path) <= 3)
        return -EACCES;

    strcat(smb_path, stripworkgroup(path));
    pthread_mutex_lock(&ctx_mutex);
    if (ctx->mkdir(ctx, smb_path, mode) < 0)
    {
        pthread_mutex_unlock(&ctx_mutex);
        return -errno;
    }
    pthread_mutex_unlock(&ctx_mutex);

    return 0;
}

static int fusesmb_utime(const char *path, struct utimbuf *buf)
{
    struct timeval tbuf[2];
    debug("path: %s, atime: %ld, mtime: %ld", path, buf->actime, buf->modtime);

    char smb_path[MY_MAXPATHLEN] = "smb:/";
    if (slashcount(path) <= 3)
        return -EACCES;

    strcat(smb_path, stripworkgroup(path));
    tbuf[0].tv_sec = buf->actime;
    tbuf[0].tv_usec = 0;
    tbuf[1].tv_sec = buf->modtime;
    tbuf[1].tv_usec = 0;

    pthread_mutex_lock(&ctx_mutex);
    if (ctx->utimes(ctx, smb_path, tbuf) < 0)
    {
        pthread_mutex_unlock(&ctx_mutex);
        return -errno;
    }
    pthread_mutex_unlock(&ctx_mutex);


    return 0;
}

static int fusesmb_chmod(const char *path, mode_t mode)
{
    if (slashcount(path) <= 3)
        return -EPERM;

    char smb_path[MY_MAXPATHLEN] = "smb:/";
    strcat(smb_path, stripworkgroup(path));

    pthread_mutex_lock(&ctx_mutex);
    if (ctx->chmod(ctx, smb_path, mode) < 0)
    {
        pthread_mutex_unlock(&ctx_mutex);
        return -errno;
    }
    pthread_mutex_unlock(&ctx_mutex);
    return 0;
}
static int fusesmb_chown(const char *path, uid_t uid, gid_t gid)
{
    (void)path;
    (void)uid;
    (void)gid;
    /* libsmbclient has no equivalent function for this, so
       always returning success
     */
    return 0;
}

static int fusesmb_truncate(const char *path, off_t size)
{

    debug("path: %s, size: %lld", path, size);
    char smb_path[MY_MAXPATHLEN] = "smb:/";
    if (slashcount(path) <= 3)
        return -EACCES;

    SMBCFILE *file;
    strcat(smb_path, stripworkgroup(path));
    if (size == 0)
    {
        pthread_mutex_lock(&ctx_mutex);
        if (NULL == (file = ctx->creat(ctx, smb_path, 0666)))
        {
            pthread_mutex_unlock(&ctx_mutex);
            return -errno;
        }
#ifdef HAVE_LIBSMBCLIENT_CLOSE_FN
        ctx->close_fn(ctx, file);
#else
        ctx->close(ctx, file);
#endif
        pthread_mutex_unlock(&ctx_mutex);
        return 0;
    }
    else
    {
         /* If the truncate size is equal to the current file size, the file
            is also correctly truncated (fixes an error from OpenOffice)
            */
         pthread_mutex_lock(&ctx_mutex);
         struct stat st;
         if (ctx->stat(ctx, smb_path, &st) < 0)
         {
             pthread_mutex_unlock(&ctx_mutex);
             return -errno;
         }
         pthread_mutex_unlock(&ctx_mutex);
         if (size == st.st_size)
         {
             return 0;
         }
    }
    return -ENOTSUP;
}

static int fusesmb_rename(const char *path, const char *new_path)
{
    char smb_path[MY_MAXPATHLEN]     = "smb:/",
         new_smb_path[MY_MAXPATHLEN] = "smb:/";

    if (slashcount(path) <= 3 || slashcount(new_path) <= 3)
        return -EACCES;

    strcat(smb_path, stripworkgroup(path));
    strcat(new_smb_path, stripworkgroup(new_path));

    pthread_mutex_lock(&ctx_mutex);
    if (ctx->rename(ctx, smb_path, ctx, new_smb_path) < 0)
    {
        pthread_mutex_unlock(&ctx_mutex);
        return -errno;
    }
    pthread_mutex_unlock(&ctx_mutex);
    return 0;
}

static int fusesmb_setxattr(const char* path, const char* name, const char* value,
    size_t size, int flags)
{
	printf("fusesmb_setxattr path=%s\n", path);

    (void)path;
    (void)name;
    (void)value;
    (void)size;
    (void)flags;
    return -EACCES;
}

static int fusesmb_getxattr(const char* path, const char* name, char* value,
    size_t size)
{
	printf("fusesmb_getxattr path=%s size=%ld\n", path, size);

    if (strcmp(name, "BEOS:TYPE") != 0)
        return -ENOATTR;

    char temp[256];
    if (size == 0) {
        value = &temp[0];
        size = sizeof(temp);
    }

    switch (slashcount(path)) {
        case 1:
            // Workgroup folder
            strlcpy(value, kWorkgroupFolderMimeType, size);
            break;

        case 2:
            // Server folder
            strlcpy(value, kServerFolderMimeType, size);
            break;

        case 3:
            // Share folder
            strlcpy(value, kShareFolderMimeType, size);
            break;

        default:
            // File or folder in share
            return -ENOATTR;
    }

    return strlen(value) + 1;
}

static int fusesmb_listxattr(const char* path, char* list, size_t size)
{
	printf("fusesmb_listxattr path=%s size=%ld (ret %ld)\n", path, size, sizeof(kMimeTypeAttributeName));
    (void)path;
    if (size > 0)
        strlcpy(list, kMimeTypeAttributeName, size);
    return sizeof(kMimeTypeAttributeName);
}

static int fusesmb_removexattr(const char* path, const char* name)
{
	printf("fusesmb_removexattr path=%s\n", path);
    (void)path;
    (void)name;
    return -EACCES;
}

static void *fusesmb_init(struct fuse_conn_info* info)
{
    (void)info;
    if (0 != pthread_create(&cleanup_thread, NULL, smb_purge_thread, NULL))
        exit(EXIT_FAILURE);
    return NULL;
}

static void fusesmb_destroy(void *private_data)
{
    (void)private_data;
    pthread_cancel(cleanup_thread);
    pthread_join(cleanup_thread, NULL);

}

static int fusesmb_getfsinfo(struct fs_info* info)
{
    memset(info, 0, sizeof(*info));
    info->flags = B_FS_IS_PERSISTENT | B_FS_IS_SHARED
        | B_FS_HAS_ATTR | B_FS_HAS_MIME;
        // TODO: find out if read-only
    info->block_size = 4096;
    info->io_size = 128 * 1024;
    info->total_blocks = (100ULL * 1024 * 1024 * 1024) / info->block_size;
    info->free_blocks = info->total_blocks;
    info->total_nodes = 100;
    info->free_nodes = 100;
    strlcpy(info->volume_name, "SMB Network", sizeof(info->volume_name));
    return 0;
}

static struct fuse_operations fusesmb_oper = {
    fusesmb_getattr,		// getattr
    NULL,					// readlink
    NULL,					// getdir
    fusesmb_mknod,			// mknod
    fusesmb_mkdir,			// mkdir
    fusesmb_unlink,			// unlink
    fusesmb_rmdir,			// rmdir
    NULL,					// symlink
    fusesmb_rename,			// rename
    NULL,					// link
    fusesmb_chmod,			// chmod
    fusesmb_chown,			// chown
    fusesmb_truncate,		// truncate
    fusesmb_utime,			// utime
    fusesmb_open,			// open
    fusesmb_read,			// read
    fusesmb_write,			// write
    fusesmb_statfs,			// statfs
    NULL,					// flush
    fusesmb_release,		// release
    NULL,					// fsync
    fusesmb_setxattr,		// setxattr
    fusesmb_getxattr,		// getxattr
    fusesmb_listxattr,		// listxattr
    fusesmb_removexattr,	// removexattr
    fusesmb_opendir,		// opendir
    fusesmb_readdir,		// readdir
    fusesmb_releasedir,		// releasedir
    NULL,					// fsyncdir
    fusesmb_init,			// init
    fusesmb_destroy,		// destroy
    NULL,					// access
    fusesmb_create,			// create
	NULL,					// ftruncate
	NULL,					// fgetattr
	NULL,					// lock
	NULL,					// utimens
	NULL,					// bmap
    fusesmb_getfsinfo		// get_fs_info
};


int main(int argc, char *argv[])
{
	gHasHaikuFuseExtensions = 1;

    /* Check if the directory for smbcache exists and if not so create it */
    int status = create_settings_dir();
    if (status != 0)
        exit(EXIT_FAILURE);

    struct stat st;
    char configfile[1024];
    get_path_in_settings_dir(&configfile[0], sizeof(configfile),
        "fusesmb.conf");
    if (-1 == stat(configfile, &st))
    {
        if (errno != ENOENT)
        {
            fprintf(stderr, strerror(errno));
            exit(EXIT_FAILURE);
        }
        int fd;
        /* Create configfile with read-write permissions for the owner */
        if (-1 == (fd = open(configfile, O_WRONLY | O_CREAT, 00600)))
        {
            fprintf(stderr, strerror(errno));
            exit(EXIT_FAILURE);
        }
        close(fd);
    }
    else
    {
        /* Check if configfile is only accessible by the owner */
        if ((st.st_mode & 00777) != 00700 &&
             (st.st_mode & 00777) != 00600 &&
              (st.st_mode & 00777) != 00400)
        {
            fprintf(stderr, "The config file should only be readable by the owner.\n"
                            "You can correct the permissions by executing:\n"
                            " chmod 600 %s\n\n", configfile);
            exit(EXIT_FAILURE);
        }
    }
    /* Check if fusesmb-scan can be found
       we're looking in FUSESMB_SCAN_BINDIR, $PATH or in cwd */
    if (-1 == stat(FUSESMB_SCAN_BINDIR"/fusesmb-scan", &st))
    {
        if (-1 == stat("fusesmb-scan", &st))
        {
            fprintf(stderr, "Could not find the required file fusesmb-scan.\n"
                            "This file should either be in:\n"
                            " - "FUSESMB_SCAN_BINDIR"\n"
                            " - $PATH\n"
                            " - your current working directory\n"
                            "(%s)\n", strerror(errno));
            exit(EXIT_FAILURE);
        }
        else
        {
            strncpy(fusesmb_scan_bin, "fusesmb-scan", MAXPATHLEN-1);
        }
    }
    else
    {
        strncpy(fusesmb_scan_bin, FUSESMB_SCAN_BINDIR"/fusesmb-scan", MAXPATHLEN-1);
    }

    if (-1 == config_init(&cfg, configfile))
    {
        fprintf(stderr, "Could not open config file: %s (%s)", configfile, strerror(errno));
        exit(EXIT_FAILURE);
    }

    options_read(&cfg, &opts);

    register_mime_types();

    ctx = fusesmb_new_context(&cfg, &cfg_mutex);
    rwd_ctx = fusesmb_new_context(&cfg, &cfg_mutex);

    if (ctx == NULL || rwd_ctx == NULL)
        exit(EXIT_FAILURE);

    fuse_main(argc, argv, &fusesmb_oper, NULL);

    smbc_free_context(ctx, 1);
    smbc_free_context(rwd_ctx, 1);

    options_free(&opts);
    config_free(&cfg);

    exit(EXIT_SUCCESS);
}
