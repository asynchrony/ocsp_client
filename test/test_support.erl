-module(test_support).

-compile([export_all]).

read_data(Filename) ->
    Path = filename:join(["../test/data", Filename]),
    {ok, Bytes} = file:read_file(Path),
    Bytes.

read_pem_data(Filename) ->
    public_key:pem_decode(read_data(Filename)).

decode_pem_entry(Filename) ->
    [Entry] = read_pem_data(Filename),
    public_key:pem_entry_decode(Entry).

decode_pem_file(Filename) ->
    [ public_key:pem_entry_decode(Entry) || Entry <- read_pem_data(Filename) ].
