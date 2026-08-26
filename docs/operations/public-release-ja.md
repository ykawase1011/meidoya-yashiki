# Public化前のセキュリティ確認

このリポジトリをprivateからpublicへ変更すると、ソースだけでなく到達可能なGit履歴、
Pull Requestの差分、Actionsの履歴・ログ・artifactも第三者から参照可能になります。
現在のbranchだけを確認して公開しません。

## 必須確認

```bash
# 現在のcheckout
gitleaks dir . --redact=100

# 全commit・branch・tag
gitleaks git . --redact=100

pnpm audit:dependencies
pnpm typecheck
pnpm build
pnpm lint
pnpm test
```

- `.env`、token、秘密鍵、SQLite、runtime data、ローカル設定が追跡されていないこと。
- 実ユーザーのhome path、メールアドレス、サービスのaccount／channel IDがないこと。
- GitHub Actions／Dependabot／Codespaces secretは名前だけを棚卸しし、不要なら削除すること。
- workflow logs、cache、artifactも公開対象として確認すること。
- commit author emailにはGitHubのnoreply addressを使うこと。
- 公開後にsecret scanning、push protection、private vulnerability reportingを有効化すること。

## 履歴を公開しない場合

旧リポジトリをprivate archiveとして別名で保持し、監査済みの現在treeから新しいpublic
リポジトリを1 commitで作る方法を推奨します。単なるorphan commitのforce-pushでは、
既存Pull RequestのrefsやGitHub上のcached viewが旧commitを参照し続ける可能性が
あります。旧リポジトリをpublicへ切り替えないことで、過去のActionsログ、cache、
artifactも非公開のまま分離できます。

実credentialを一度でもcommitした場合は、履歴操作より先にcredentialを失効・rotate
します。force-pushだけで漏洩が取り消されたとは判断しません。

## 1 commit公開手順

1. private版の`main`で上記確認をすべて通す。
2. 旧リポジトリを`meidoya-yashiki-private-archive`などへ改名し、privateのまま保持する。
3. `git archive`で監査済みtreeだけを別ディレクトリへ展開する。
4. GitHub noreply emailで新しい`main`を初期化し、`Initial public release`の1 commitを作る。
5. 新しいpublicリポジトリ`meidoya-yashiki`へpushする。
6. secret scanning、push protection、private vulnerability reporting、branch protectionを有効化する。
7. public側のCIが成功し、commit数が1であることを確認する。
