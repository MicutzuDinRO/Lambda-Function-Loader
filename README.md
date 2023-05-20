# so-hackathon

### Members: Jumărea Ștefan-Dorin, Micu Alexandru, 331CC
### https://gitlab.cs.pub.ro/stefan.jumarea/so-hackathon

## Basic Functionality

The project is proposing to implement a very simple lambda server.

The project uses multiprocessing, over on a basic TCP connection.

The main process waits for connections, then open a new process for every client that
connects. We chose to go with the multiprocess approach in order to maximize
the safety and sandboxing of every client, since the client will choose what
functions to run, and the functions themselves can lead to memory errors, exit
points and other similar problems that can cause issues if using a multithreaded
approach.
The output of the chosen file is sent back through a temporary file.

The server must be run with:

```console
LD_LIBRARY_PATH=.:../checker/ ./server [OPTIONS]
```

## Extra functionalities

The project has the following extra functionalities:

* Application logs, in 4 levels: `debug`, `info`, `warning` and `error`.
  This can be used by passing `--log-level=info` to the server.
  The log is saved in a file named "server.log", in the same directory where
  the server was ran from.

  ```console
  skel/$    LD_LIBRARY_PATH=.:../checker ./server --log-level=debug

  checker/$ ./client libbasic.so

  skel/$   cat server.log
  DEBUG: Opening library: libbasic.so
  INFO: Executing function: run
  DEBUG: Closing library: libbasic.so
  ```

* Network sockets usage, along with the default Unix sockets.
  There is a new client implemented (`./client_net`), that works just like the
  testing client, but over network sockets.
  The server can be run to use network sockets by passing the `--network`, `--net`
  or `--n` options.

  ```console
  skel/$    LD_LIBRARY_PATH=.:../checker ./server --network

  skel/$ ./client_net ../checker/libbasic.so
  Output file: [...]
  ```

* A client that can send multiple queries to the server, until it types in `exit`
  or `quit`. The client is `./client_multi`, and can be run without any extra
  options.

  ```console
  skel/$    LD_LIBRARY_PATH=.:../checker ./server

  skel/$ ./client_multi
  ../checker/libbasic.so run
  Output file [...]
  ../checker/libbasic.so cat file
  Output file [...]
  exit
  ```

* Real time statistics that can be used by passing the `--show-stats` option to the
  server. It will print the number of page faults and context switches (voluntary
  and involuntary) at the stderr of the server.

  ```console
  skel/$    LD_LIBRARY_PATH=.:../checker ./server --show-stats
  Server voluntary ctx switches: 3
  Server involuntary ctx switches: 0
  Server page faults: 102
  Server voluntary ctx switches: 3
  Server involuntary ctx switches: 0
  Server page faults: 204

  checker/$ ./client libbasic.so
  checker/$ ./client libbasic.so
  ```

* External configuration file. It can be used by passing the `--config FILENAME`
  options to the server. There is already a config file example in the repo.
  The configuration file should have the following format:

  ```text
  log-level=info
  network=true
  show-stats=true
  ```

  ```console
  skel/$    LD_LIBRARY_PATH=.:../checker ./server --config server.config
  ```

  All the options can be found by running `./server --help`.

* Graceful exit. When pressing CTRL+C (or sending SIGINT via any other way), the
  signal is caught, all the resources are freed and children waited.
