# Auxiliary File Generation Tool

This tool generates the binary file used to verify the state of a module after execution and revert it to it's original
state. Any rule specified in the configuration file will be 1. Reverted and 2. Verified (depending on the verification type).

`create-aux` -> Consumes a configuration file to generate an auxiliary file.
`create-config` -> Creates a new config with 100% coverage, but all rules are `none`.
`test-aux` -> Tests if the aux file validation rules pass against a dumped efi image.

## Auxiliary File Format

```text
+--------------------------------------------+
+  IMAGE_VALIDATION_DATA_HEADER
+--------------------------------------------+
+  KEY_SYMBOL[]
+--------------------------------------------+
+  IMAGE_VALIDATION_ENTRY_HEADER[]
+--------------------------------------------+
+  Defaults
+--------------------------------------------+
```

## Usability

Check the tool's help information by using the command `cargo run -- -h` or if the tool is already compiled, `gen_aux -h`.
It will provide you a list of options and a brief description of each option

## The Configuration File

The configuration file, passed to the executable via the `-c` command, is used to specify which symbols should be reverted
to their original value and/or tested using one of the supported testing methods. The config file uses the [toml](https://toml.io/en/)
format for setting config options in the file. Currently, there are two configuration options: `rule` and `autogen`

### key

the key command (`[[key]]`) is a configuration option to tell the tool to generate signature / offset pairs for a specific
symbol and add them to the the header (`IMAGE_VALIDATION_DATA_HEADER`).

``` toml
[[key]]
signature = 'Required[[char; 4]]'
symbol = 'Optional[String]'
offset = 'Optional[u32]'
```

- `signature`: The 4 byte signature used by the firmware to determine how to use the offset (i.e. ['F', 'P', 'O', 'L'])
- `symbol`: Used to calculate the offset value. Mutually exclusive to `offset`
- `offset`: The offset used by the firmware. Mutually exclusive to `symbol`

### rule

The rule command (`[[rule]]`) is a configuration option to tell the tool to generate an entry header for the specific
symbol. If the specific symbol is an array, then a entry header will be generated for each entry in the array. The rule
comes with the following standard options:

``` toml
[[rule]]
scope = 'Optional[String]'
symbol = 'Required[String]'
field = 'Optional[String]'
array.index = 'Optional[Int]'|'Optional[Array[Int;2]]'
array.sentinel = 'Optional[Boolean]'
validation.type = 'Required[String]'
reviewed-by = 'Optional[Array[String]]'
last-reviewed = 'Optional[String]'
remarks = 'Optional[String]'
```

- `scope`: If specified, the rule is only applied when this scope is active. Otherwise it is always applied.
- `symbol`: Determines the address and size for the rule
- `field`: Updates the address and size to be that of the field, rather than the symbol itself.
- `array.index`: Only apply the rule to the specified index of the array, or inclusive range
- `array.sentinel`: Apply content rule to only the final rule such that its content must be all zeros.
- `validation.type`: The type of validation to perform on this symbol. Different values may also require additional configuration
settings in the `[[rule]]`.
- `reviewed-by`: A list of reviewers using git sign-off format of `First Last <email>`. This value is passed through to
the final report.
- `last-reviewed`: The date this rule was last reviewed, with the format YYYY-MM-DD.
- `remarks`: Additional context to this rule / symbol and why the validation type was selected.

#### Validation Type: None

The None validation type tells the system to perform no verification on this symbol. This rule is available for symbols
that do not need to be verified, but do need to be reverted back to their original value before execution. This rule has
no additional configuration options.

``` toml
[[rule]]
validation.type = "none"
```

#### Validation Type: Non Zero

The non zero validation type tells the system to verify that the value of the symbol is not zero / null. This rule has no
additional configuration options.

``` toml
[[rule]]
validation.type = "non zero"
```

#### Validation Type: Content

The content validation type tells the system to verify that the value of the symbol is equal to the value provided via the
`validation.content` configuration option. The length of the content, and the size of the symbol should match.

``` toml
[[rule]]
validation.type = "content"
validation.content = [] # Vec of bytes
```

#### Validation Type: Memory Attribute

The Memory attribute validation type tells the system to verify that the buffer behind the reference at the specified address
matches the memory size and must_have / must_not have's.

``` toml
validation.type = "mem attr"
validation.memory_size = "Required[int]"
validation.must_have = "Required[int]"
validation.must_not_have = "Required[int]"
```

#### Validation Type: Self Reference

The self reference attribute verifies that the value of a symbol is equal to the value of another symbol, or the content
at a specific address. `validation.reference` and `validation.address` is mutually exclusive.

``` toml
validation.type = "self"
validation.reference = "Optional[String]"
validation.address = "Optional[int]"
```

#### Validation Type: Pointer

The pointer validation type verifies that the symbol is in-fact a pointer and subject to pointer-specific validation
such as not being null.

``` toml
validation.type = "pointer"
validation.in_mseg = true # Default: false
```

#### Validation Type: Guid

The guid validation type verifies that a symbol representing a guid is the expected guid value. Behind the scenes,
this rule simply generates a `Content` rule of the bytes, but does the conversion for you.

``` toml
validation.type = "guid"
validation.guid = [0x0, 0x0, 0x0, [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]]
```

### config

The below configuration options reside in a top level `[config]` section of the configuration file.

``` toml
[config]
no_missing_rules = true
```

#### no_missing_rules

`no_missing_rules = true/false` config option tells the tool to stop processing if there is a symbol that does not
currently have a rule created.

## Adding a new rule

1. Add the new validation type to the `ValidationType` enum in `validation.rs`. Any data added to this enum will be automatically
available to the user to provide via the config file, and will also be the content that should be written to the entry header
data. Update the `into` function directly below it to the new header type u32 value as specified in C code.

2. Update the match statement `ImageValidationEntryHeader.header_size` function in `auxgen.rs` to return the size of any
extra data that will be written to the header (other than the header itself).

3. Update the match statement in `ImageValidationEntryHeader.try_into_ctx` to write the extra data to the buffer.
