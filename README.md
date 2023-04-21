<!-- Allow this file to not have a first line heading -->
<!-- markdownlint-disable-file MD041 no-emphasis-as-heading -->

<!-- inline html -->
<!-- markdownlint-disable-file MD033 -->

<div align="center">

# `💩 webpurify-client`

**Super simple client for the Webpurify REST API**

<!--- FIXME: Update crate, repo and CI workflow names here! Remove any that are not relevant --->
[![Embark](https://img.shields.io/badge/embark-open%20source-blueviolet.svg)](https://embark.dev)
[![Embark](https://img.shields.io/badge/discord-embark-%237289da.svg?logo=discord)](https://discord.gg/dAuKfZS)

[//]: # ([![Crates.io]&#40;https://img.shields.io/crates/v/rust-gpu.svg&#41;]&#40;https://crates.io/crates/rust-gpu&#41;)
[//]: # ([![Docs]&#40;https://docs.rs/rust-gpu/badge.svg&#41;]&#40;https://docs.rs/rust-gpu&#41;)
[//]: # ([![Git Docs]&#40;https://img.shields.io/badge/git%20main%20docs-published-blue&#41;]&#40;https://embarkstudios.github.io/presser/presser/index.html&#41;)
[//]: # ([![dependency status]&#40;https://deps.rs/repo/github/EmbarkStudios/rust-gpu/status.svg&#41;]&#40;https://deps.rs/repo/github/EmbarkStudios/rust-gpu&#41;)
[//]: # ([![Build status]&#40;https://github.com/EmbarkStudios/physx-rs/workflows/CI/badge.svg&#41;]&#40;https://github.com/EmbarkStudios/physx-rs/actions&#41;)
</div>

## What is this?

An incredibly small library to interact with the https://www.webpurify.com/documentation/ REST API.

`webpurify-client` takes the [sans-io](https://sans-io.readthedocs.io/) approach and builds up the request objects for you so that you can use whatever library you're used to for the actual HTTP transport.

See the example code on how to use it `webpurify-client` together with [reqwest](https://crates.io/crates/reqwest)
## Examples

Build and run the provided example:

```bash
$ cargo run --example profanity -- --apikey <your-webpurify-api-key>
=> 
 
{
  status: 200,
  version: HTTP/2.0,
  headers: { ... },
  body: {
    "rsp": {
      "@attributes": {
        "stat": "ok",
        "rsp": "0.062274932861328"
      },
      "method": "webpurify.live.replace",
      "format": "rest",
      "found": "3",
      "text": "**** you man! call me at +**********3 or email me at ****.****@*******.***",
      "api_key": "some-api-key"
    }
  }
}
```

## Supported methods

The following webpurify methods are currently available:

```rust
pub enum Method {
    /// webpurify.live.check
    Check,
    /// webpurify.live.check
    Replace(String),
}
```

[//]: # (## TEMPLATE INSTRUCTIONS)

[//]: # ()
[//]: # (1. Create a new repository under EmbarkStudios using this template.)

[//]: # (1. **Title:** Change the first line of this README to the name of your project, and replace the sunflower with an emoji that represents your project. 🚨 Your emoji selection is critical.)

[//]: # (1. **Badges:** In the badges section above, change the repo name in each URL. If you are creating something other than a Rust crate, remove the crates.io and docs badges &#40;and feel free to add more appropriate ones for your language&#41;.)

[//]: # (1. **CI:** In `./github/workflows/` rename `rust-ci.yml` &#40;or the appropriate config for your language&#41; to `ci.yml`. And go over it and adapt it to work for your project)

[//]: # (    - If you aren't using or customized the CI workflow, also see the TODO in `.mergify.yml`)

[//]: # (    - If you want to use the automatic rustdoc publishing to github pages for git main, see `rustdoc-pages.yml`)

[//]: # (1. **Issue & PR Templates**: Review the files in `.github/ISSUE_TEMPLATE` and `.github/pull_request_template`. Adapt them)

[//]: # (to suit your needs, removing or re-wording any sections that don't make sense for your use case.)

[//]: # (1. **CHANGELOG.md:** Change the `$REPO_NAME` in the links at the bottom to the name of the repository, and replace the example template lines with the actual notes for the repository/crate.)

[//]: # (1. **release.toml:** in `./release.toml` change the `$REPO_NAME` to the name of the repository)

[//]: # (1. **Cleanup:** Remove this section of the README and any unused files &#40;such as configs for other languages&#41; from the repo.)

## Contributing

[![Contributor Covenant](https://img.shields.io/badge/contributor%20covenant-v1.4-ff69b4.svg)](CODE_OF_CONDUCT.md)

We welcome community contributions to this project.

Please read our [Contributor Guide](CONTRIBUTING.md) for more information on how to get started.
Please also read our [Contributor Terms](CONTRIBUTING.md#contributor-terms) before you make any contributions.

Any contribution intentionally submitted for inclusion in an Embark Studios project, shall comply with the Rust standard licensing model (MIT OR Apache 2.0) and therefore be dual licensed as described below, without any additional terms or conditions:

### License

This contribution is dual licensed under EITHER OF

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

For clarity, "your" refers to Embark or any other licensee/user of the contribution.
