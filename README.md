<a href="https://www.theta.co.nz/solutions/cyber-security/">
<img src="https://avatars0.githubusercontent.com/u/2897191?s=70&v=4" 
title="Theta Cybersecurity" alt="Theta Cybersecurity">
</a>

<!-- security tools - submodule repo -->
<!-- josh.highet@theta.co.nz -->

# securitytools

This repository hosts an array of GitHub projects leveraged across the security community, indexed as submodules.

## updating submodules

![Update Submodules](https://github.com/thetanz/securitytools/workflows/Update%20Submodules/badge.svg)

A GitHub Action updates all recursive submodules at a weekly cadence.

An immediate update of can be initiated by navigating to the [Workflow Summary](https://github.com/thetanz/securitytools/actions?query=workflow%3A%22Update+Submodules%22) and hitting `Run Workflow`.

## adding submodules

Adding a submodule can be done by navigating to an applicable folder and replacing `git clone` with `git submodule add` when you bring down a repo.

_If you have placed the reposotory into the wrong folder, follow the steps to remove it before trying again._

## removing submodules

  1. delete the relevant section from `.gitmodules`.
  2. stage the `.gitmodules` changes with `git add .gitmodules`
  3. delete the relevant section from `.git/config`
  4. run `git rm --cached path_to_submodule` (no trailing slash).
  5. run `rm -rf .git/modules/path_to_submodule` (no trailing slash).
  6. commit changes `git commit -m "submodule removal"`
  7. delete submodule files `rm -rf path_to_submodule`

---

[Theta](https://theta.co.nz)