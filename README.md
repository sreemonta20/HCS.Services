## Introduction

This is a Backend security web api service, which is built on .NET 6 (Main Security API service and Email service). It can be used for whole security management of any microservice. It is built on such a way that it could be integrated in future for microservices. API gayeway (Ocelot) will be introduced soon. 

# Reference links

- [GitLab CI Documentation](https://docs.gitlab.com/ee/ci/)
- [.NET Hello World tutorial](https://dotnet.microsoft.com/learn/dotnet/hello-world-tutorial/)

If you're new to .NET you'll want to check out the tutorial, but if you're
already a seasoned developer considering building your own .NET app with GitLab,
this should all look very familiar.

## What's contained in this project

It contains 
1. the core security feature for user management such as registering and updating user, 
list of all user, get a specific user, delete a user. 
2. These are the operation can be done by administrator after login. 
3. Token management is taken care of.
4. After 3 failed attempts, user can be locked out for 1 min. Also user can modify such settings from appsettings.json. 
5. Email configuration is well configured. Google email is a populr domain for testing whether email has been pushed or not after 3 consecutive failed attempt for login. Due to this , email settings is initialized for smtp.gmail.com. User can change into their domain and test email sending events.




```
image: microsoft/dotnet:latest
```

We're defining two stages here: `build`, and `test`. As your project grows
in complexity you can add more of these.

```
stages:
    - build
    - test
```

Next, we define our build job which simply runs the `dotnet build` command and
identifies the `bin` folder as the output directory. Anything in the `bin` folder
will be automatically handed off to future stages, and is also downloadable through
the web UI.

```
build:
    stage: build
    script:
        - "dotnet build"
    artifacts:
      paths:
        - bin/
```

Similar to the build step, we get our test output simply by running `dotnet test`.

```
test:
    stage: test
    script: 
        - "dotnet test"
```

This should be enough to get you started. There are many, many powerful options 
for your `.gitlab-ci.yml`. You can read about them in our documentation 
[here](https://docs.gitlab.com/ee/ci/yaml/).

## Developing with Gitpod

This template repository also has a fully-automated dev setup for [Gitpod](https://docs.gitlab.com/ee/integration/gitpod.html).

The `.gitpod.yml` ensures that, when you open this repository in Gitpod, you'll get a cloud workspace with .NET Core pre-installed, and your project will automatically be built and start running.
