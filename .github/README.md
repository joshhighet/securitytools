```shell
git -C <path> clone https://github.com/<repo>
```

```shell
git submodule add https://github.com/<repo>
```

```shell
git submodule init
git submodule update
git submodule deinit -f <repo>
rm -rf .git/modules/<repo>
git rm -f <repo>
git commit -m "removed <repo>"
```
