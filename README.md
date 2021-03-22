# s3-sysbackup Package

A very flexible, Unix-style facility for backing content up to **AWS S3** with time/space folding, using the S3 **Object Lock** system for *write-once-read-many* (WORM) storage, which can help provide additional security or compliance around backup requirements.

S3 charges not only for storage, but also for transfer of data into S3.  `s3-sysbackup` works to minimize both kinds of charges, including a limited ability to amortize backup content storage over multiple machines.

## Configuration

`s3-sysbackup` configuration lives in a directory structure on disk, with the default location being `/etc/backup`.  Within the directory there must be a `conf` file, which is in Python [*configparser*][configparser] format.  Backup strategies, as detailed below, each have their own subdirectory of the configuration directory.

The sections of the `conf` file are detailed in the subsections below.

### `conf` File: `[aws]` Section

This section gives configuration information for access to the AWS API.  The available settings are:

| Setting | Value Description     |
| :------------- | :-------------------------------------------------------- |
| `profile` | Sets the profile to use -- may be from the standard profile system or from a custom credentials file specified with the `credentials_file` setting |
| `credentials_file` | Path to an AWS credentials file to use |
| `role_arn` | Used only in conjunction with the `credentials_file` setting, gives the ARN of an IAM Role to assume for authorizing AWS actions |

Please note that, if `credentials_file` is *not* used, `profile` can be used to identify a standardly configured AWS profile that uses an assumed IAM Role, which is why the `role_arn` setting only works if a `credentials_file` is given.

### `conf` File: `[s3]` Section

This section configures usage of S3.  The available settings are:

| Setting | Value Description |
| :------------- | :-------------------------------------------------------- |
| `bucket` | Explicitly sets the name of the bucket into which the backup should be made; if not given (or explicitly set on the `Saver` before `load_config` is called), CloudFormation is used to identify the bucket |

### `conf` File: `[cloudformation]` Section

When an S3 bucket is not explicitly configured either on the `Saver` object or through the `bucket` setting in the `[s3]` section, the `Saver` will attempt to query CloudFormation for an export – named `backup-bucket`, unless otherwise specified as indicated below – giving the name of the destination bucket.

| Setting | Value Description |
| :------------- | :-------------------------------------------------------- |
| `region` | AWS region in which the CloudFormation stack to be queried resides; if the profile in use does not configure a default region, this is necessary for use of CloudFormation |
| `export` | The name of the export to read for the bucket name |

### `conf` File: `[content]` Section

| Setting | Value Description |
| :------------- | :-------------------------------------------------------- |
| `lock_timeout` | The number of seconds to wait for an advisory read lock on a "picked" file |
| `days_retained` | The number of days for which content should be retained via S3's Object Lock |

## Backup Strategies

`s3-sysbackup` employs two different strategies for backup: a file-based strategy called *quilting* and a dynamic data strategy called *snapshotting*.  Information from both strategies is included in the *manifest file* uploaded to S3 for each backup run on each machine.

### Quilting

Quilting, like the Git version control system, is content based: it keys the objects in which it stores content on S3 by the content found within the file.  The keys for these objects are then "patched together" (i.e. *quilted*) by the information this strategy incorporates into the manifest file uploaded for each backup.  When a file's content hasn't changed since the last backup, that file content need not be uploaded again.  And when multiple machines are backing up copies of the same file, the file content only needs to be uploaded by the first machine to back it up.

The manifest, like a recursive version of Git's *trees*, has entries referencing a file's content, path on the system, and permissions, but also its ownership.  It also contains information about symbolic links and directories, so as much as possible of the backed-up system can be restored.  Where possible, ownership uses symbolic names and permissions are captured as ACLs, but fallbacks to numeric representations can occur.

Selection of files for the quilting strategy is done by executables placed (or symlinked into) in the `pickers.d` subdirectory of the configuration directory.  Each executable file in that directory is run and the lines it prints to STDOUT are interpreted as file paths; one typical usage is to put one or more executable shell scripts that call `find` with the desired parameters.

To save on transfer and storage costs with S3, each file selected by a *picker* will be evaluated as to whether gzipping will improve storage efficiency.  If the test indicates that the file compresses well, the GZip algorithm will be applied before the file is transferred to S3; the application of GZip will be noted on the S3 object's metadata.

### Snapshotting

Not all data to be backed up resides conveniently in a file that can be assumed unchanging or reasonably readable at a given moment, with databases as a good example.  For these data, it is typically necessary to invoke a tool both to retrieve the backup data and also to restore it.  `s3-sysbackup` accommodates this need through its *snapshotting* strategy.

Executable files in the `snapshots.d` subdirectory of the configuration directory provide both the snapshot content and commentary about the snapshot.  Each of these executables will be invoked with a single argument: a decimal string giving the file descriptor to which it should write the snapshot data.  Text sent to STDOUT is captured as a description of the snapshot included in the S3 object's metadata.  A line sent to STDOUT starting with `::restore-through::` is interpreted as giving a (shell formatted) command for restoring the snapshot data (piped to STDIN) onto a system, which is additionally saved in a separate metadata entry.

With each run of the backup system, each snapshot will be taken and uploaded to S3.  It is the responsibility of the snapshotter executables to implement any beneficial compression.  The object keys of all uploaded snapshot content are collected within the uploaded manifest file for the backup run.

As a note, if writing a snapshotter executable as a `bash` script, the construct `>&${1:-1}` can be useful: it redirects output to the file descriptor passed as the first argument, defaulting to STDOUT (file descriptor 1) if not specified.  This will not, of course, work within a function, though it could be adapted by copying the target descriptor number into a less general variable name:

```shell
# At top level of script
CONTENT_FD=${1:-1}

# Defining a function
function some_func() {
  # ...
  some-pipeline-producing-content >&$CONTENT_FD
  # ...
}
```

---
[configparser]: https://docs.python.org/3.6/library/configparser.html
