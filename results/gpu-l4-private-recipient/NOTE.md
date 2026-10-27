The first lines of `queue.log` come from the VM's setup log. That setup build failed
(`BUILD_EXIT=101`) because `unzip` was missing (a dependency's build script downloads a zip).
The line `BUILD_EXIT=0 (unzip installed; final.sh rebuilds)` was appended by hand after
installing `unzip`; it is not a recorded exit code. The queue below it checked out `e7ae6d8`
and rebuilt from scratch (`Finished ... in 20m 10s`) before every run.
