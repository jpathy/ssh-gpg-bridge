![Build](https://github.com/jpathy/ssh-gpg-bridge/workflows/Build/badge.svg)

# About

Currently windows ssh client requires `SSH_AUTH_SOCK` to be a Named pipe which gpg-agent [doesn't support](https://dev.gnupg.org/T3883).

Until that issue is fixed you can use this program to to use your gpg keys(including hardware keys) with native ssh client.

This program acts as a bridge to gpg-agent's Pageant support listening on a Named pipe to work as ssh-agent for windows SSH client.

## Compiling

To build this project you need MSBuild and Nuget (or Visual Studio).

```
nuget restore
msbuild -t:Rebuild -p:Configuration=Release
```

## Pre-requisites

Typically you install GnuPG with chocolatey or [direct download](https://gnupg.org/download/) and put in path.

## Usage

* Currently `SSH_AUTH_SOCK` is fixed so you can set it for your user and set this  program to launch on startup. Powershell:
  ```
  [System.Environment]::SetEnvironmentVariable(
   "SSH_AUTH_SOCK",
   "\\.\pipe\GPG_SSH_BRIDGE_SOCK",
   [System.EnvironmentVariableTarget]::User)
  ```
* To use with **Git** you need to set ssh path to native client:
  ```
  git config --global core.sshCommand "c:\\windows\\system32\\openssh\\ssh.exe"
  ```
### Behaviour
Program runs as a tray window.
Double click -> copies `SSH_AUTH_SOCK` value to clipboard.
Right click -> popup menu > `Quit` to exit.
