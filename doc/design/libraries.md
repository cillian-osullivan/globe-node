# Libraries

| Name                     | Description |
|--------------------------|-------------|
| *libglobe_cli*         | RPC client functionality used by *globe-cli* executable |
| *libglobe_common*      | Home for common functionality shared by different executables and libraries. Similar to *libglobe_util*, but higher-level (see [Dependencies](#dependencies)). |
| *libglobe_consensus*   | Stable, backwards-compatible consensus functionality used by *libglobe_node* and *libglobe_wallet* and also exposed as a [shared library](../shared-libraries.md). |
| *libglobeconsensus*    | Shared library build of static *libglobe_consensus* library |
| *libglobe_kernel*      | Consensus engine and support library used for validation by *libglobe_node* and also exposed as a [shared library](../shared-libraries.md). |
| *libglobeqt*           | GUI functionality used by *globe-qt* and *globe-gui* executables |
| *libglobe_ipc*         | IPC functionality used by *globe-node*, *globe-wallet*, *globe-gui* executables to communicate when [`--enable-multiprocess`](multiprocess.md) is used. |
| *libglobe_node*        | P2P and RPC server functionality used by *globed* and *globe-qt* executables. |
| *libglobe_util*        | Home for common functionality shared by different executables and libraries. Similar to *libglobe_common*, but lower-level (see [Dependencies](#dependencies)). |
| *libglobe_wallet*      | Wallet functionality used by *globed* and *globe-wallet* executables. |
| *libglobe_wallet_tool* | Lower-level wallet functionality used by *globe-wallet* executable. |
| *libglobe_zmq*         | [ZeroMQ](../zmq.md) functionality used by *globed* and *globe-qt* executables. |

## Conventions

- Most libraries are internal libraries and have APIs which are completely unstable! There are few or no restrictions on backwards compatibility or rules about external dependencies. Exceptions are *libglobe_consensus* and *libglobe_kernel* which have external interfaces documented at [../shared-libraries.md](../shared-libraries.md).

- Generally each library should have a corresponding source directory and namespace. Source code organization is a work in progress, so it is true that some namespaces are applied inconsistently, and if you look at [`libglobe_*_SOURCES`](../../src/Makefile.am) lists you can see that many libraries pull in files from outside their source directory. But when working with libraries, it is good to follow a consistent pattern like:

  - *libglobe_node* code lives in `src/node/` in the `node::` namespace
  - *libglobe_wallet* code lives in `src/wallet/` in the `wallet::` namespace
  - *libglobe_ipc* code lives in `src/ipc/` in the `ipc::` namespace
  - *libglobe_util* code lives in `src/util/` in the `util::` namespace
  - *libglobe_consensus* code lives in `src/consensus/` in the `Consensus::` namespace

## Dependencies

- Libraries should minimize what other libraries they depend on, and only reference symbols following the arrows shown in the dependency graph below:

<table><tr><td>

```mermaid

%%{ init : { "flowchart" : { "curve" : "linear" }}}%%

graph TD;

globe-cli[globe-cli]-->libglobe_cli;

globed[globed]-->libglobe_node;
globed[globed]-->libglobe_wallet;

globe-qt[globe-qt]-->libglobe_node;
globe-qt[globe-qt]-->libglobeqt;
globe-qt[globe-qt]-->libglobe_wallet;

globe-wallet[globe-wallet]-->libglobe_wallet;
globe-wallet[globe-wallet]-->libglobe_wallet_tool;

libglobe_cli-->libglobe_common;
libglobe_cli-->libglobe_util;

libglobe_common-->libglobe_util;
libglobe_common-->libglobe_consensus;

libglobe_kernel-->libglobe_consensus;
libglobe_kernel-->libglobe_util;

libglobe_node-->libglobe_common;
libglobe_node-->libglobe_consensus;
libglobe_node-->libglobe_kernel;
libglobe_node-->libglobe_util;

libglobeqt-->libglobe_common;
libglobeqt-->libglobe_util;

libglobe_wallet-->libglobe_common;
libglobe_wallet-->libglobe_util;

libglobe_wallet_tool-->libglobe_util;
libglobe_wallet_tool-->libglobe_wallet;

classDef bold stroke-width:2px, font-weight:bold, font-size: smaller;
class globe-qt,globed,globe-cli,globe-wallet bold
```
</td></tr><tr><td>

**Dependency graph**. Arrows show linker symbol dependencies. *Consensus* lib depends on nothing. *Util* lib is depended on by everything. *Kernel* lib depends only on consensus and util.

</td></tr></table>

- The graph shows what _linker symbols_ (functions and variables) from each library other libraries can call and reference directly, but it is not a call graph. For example, there is no arrow connecting *libglobe_wallet* and *libglobe_node* libraries, because these libraries are intended to be modular and not depend on each other's internal implementation details. But wallet code still is still able to call node code indirectly through the `interfaces::Chain` abstract class in [`interfaces/chain.h`](../../src/interfaces/chain.h) and node code calls wallet code through the `interfaces::ChainClient` and `interfaces::Chain::Notifications` abstract classes in the same file. In general, defining abstract classes in [`src/interfaces/`](../../src/interfaces/) can be a convenient way of avoiding unwanted direct dependencies or circular dependencies between libraries.

- *libglobe_consensus* should be a standalone dependency that any library can depend on, and it should not depend on any other libraries itself.

- *libglobe_util* should also be a standalone dependency that any library can depend on, and it should not depend on other internal libraries.

- *libglobe_common* should serve a similar function as *libglobe_util* and be a place for miscellaneous code used by various daemon, GUI, and CLI applications and libraries to live. It should not depend on anything other than *libglobe_util* and *libglobe_consensus*. The boundary between _util_ and _common_ is a little fuzzy but historically _util_ has been used for more generic, lower-level things like parsing hex, and _common_ has been used for globe-specific, higher-level things like parsing base58. The difference between util and common is mostly important because *libglobe_kernel* is not supposed to depend on *libglobe_common*, only *libglobe_util*. In general, if it is ever unclear whether it is better to add code to *util* or *common*, it is probably better to add it to *common* unless it is very generically useful or useful particularly to include in the kernel.


- *libglobe_kernel* should only depend on *libglobe_util* and *libglobe_consensus*.

- The only thing that should depend on *libglobe_kernel* internally should be *libglobe_node*. GUI and wallet libraries *libglobeqt* and *libglobe_wallet* in particular should not depend on *libglobe_kernel* and the unneeded functionality it would pull in, like block validation. To the extent that GUI and wallet code need scripting and signing functionality, they should be get able it from *libglobe_consensus*, *libglobe_common*, and *libglobe_util*, instead of *libglobe_kernel*.

- GUI, node, and wallet code internal implementations should all be independent of each other, and the *libglobeqt*, *libglobe_node*, *libglobe_wallet* libraries should never reference each other's symbols. They should only call each other through [`src/interfaces/`](`../../src/interfaces/`) abstract interfaces.

## Work in progress

- Validation code is moving from *libglobe_node* to *libglobe_kernel* as part of [The libglobekernel Project #24303](https://github.com/globe/globe/issues/24303)
- Source code organization is discussed in general in [Library source code organization #15732](https://github.com/globe/globe/issues/15732)
