# Trustbroker Frontend

This project was generated with [Angular CLI](https://github.com/angular/angular-cli) version 11.2.11.
To not depend on a locally installed node setup, use the gradle wrapper to use the downloaded node_modules content.

## Development server

For a dev server:

- Directly: `./npmw start`
- Via gradle: `gw npm_start` (within frontend directory)
- Run everything: `gw bootRun` (executed in project top, also starts the frontend server)
- Navigate to `http://localhost:4200/`.

The app will automatically reload if you change any of the source files.

## Build

Intgrated into gradle: `gw assemble`
Run `./npmw rebuild` to build the project. The build artifacts will be stored in the `dist/` directory.
Use the `--prod` flag for a production build.

## Running unit tests

Intgrated into gradle: `gw test`
Run `./npmw test` to execute the unit tests via [Karma](https://karma-runner.github.io).

## Running end-to-end tests

Integrated into gradle: `gw systemTest`
Requires services to be started via bootRun.

## Correct lint issues

Run `./npmw run lint -- --fix`

## Security

Run `./npmw audit` to check for vulnerabilities.

## Further help

Integrated into gradle: gw npm_help
Run `./npmw help`

## Upgrade to Angular 15.0

https://update.angular.io/?v=14.0-15.0

As preparation the dependencies were bumped to versions supported by both Angular versions. That is not a necessity but it allows stepwise update and verification.

## Update to Oblique 10

Oblique 9 could be updated to 10 independently of Angular:

https://oblique.bit.admin.ch/getting-started/update-oblique

Deprecations were resolved prior to upgrading.

## Karma Tests

To run the tests manually (with more output than from gw npmRunTests):

```
google-chrome --headless --remote-debugging-port=4444
ng test --watch false "--code-coverage" "--no-progress" "--browsers=ChromeHeadless"
```

## Install Docker on RHEL 9

Note that RHEL 9 comes with the daemonless podman-docker by default, but our test needs a docker daemon to run.
You can install docker-ce from the Docker CentOS repo (their RHEL repo lacks the x86 version):

```
sudo yum remove podman-docker
sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
sudo yum install docker-ce
sudo yum-config-manager --disable docker-ce-stable
sudo systemctl restart docker
```

Then load the image (using the version from browserDocker.imageTag):
`docker install <docker-repo>/selenium/standalone-chrome:3.141.59-20210422`

## Generate Data URLs from SVGs

In `src/assets/images/[theme]`:

```
for f in help.svg arrow_down.svg globe.svg light.svg dark.svg ; do echo "# $f"; cat $f  | base64 | awk ' BEGIN { printf "content: url(\"data:image/svg+xml;base64," }  { printf $0 } END { print "\");" } '; done
```
