# ipatools

`ipatools` is a small, dependency-free Go CLI for authorized mobile-security
workflows. It delegates App Store authentication and acquisition to the
open-source [`majd/ipatool`](https://github.com/majd/ipatool), then validates
the downloaded IPA, calculates SHA-256, and can create a `.zip` copy for static
inspection.

It never accepts an Apple Account email, password, 2FA code, or keychain
passphrase. Authenticate privately first:

```text
ipatool auth login
```

Then use the wrapper:

```text
ipatools status
ipatools download --app-id 632064380 --output downloads/vinted.ipa --zip --authorized
ipatools inspect --input downloads/vinted.ipa
ipatools to-zip --input downloads/vinted.ipa
```

An IPA is already a ZIP-format archive. `--zip` creates a byte-for-byte copy
with a `.zip` extension; it does not decrypt, resign, or bypass DRM.

Only download software your Apple Account is entitled to obtain, and only
assess applications for which you have explicit authorization.

## Build

```text
go test ./...
go build -o ipatools .
```

Set `IPATOOL_BIN` to an absolute upstream executable path when `ipatool` is not
on `PATH`.

## License

MIT
