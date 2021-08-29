-module(test).
-compile(export_all).

-type name() :: iodata().

-spec encode_name(name()) -> binary().

encode_label(Label) ->
    BinLabel = iolist_to_binary(Label),
    <<(byte_size(BinLabel)):8, BinLabel/binary>>.

encode_name(TextDomain) ->
    Domain = iolist_to_binary(TextDomain),
    UnencodedLabels = binary:split(Domain, <<".">>, [global]),
    Labels = << (encode_label(U)) || U <- UnencodedLabels >>,
    <<Labels/binary, 0:8>>.

-type type() :: 'A'
              | 'NS'
              | 'MD'
              | 'MF'
              | 'CNAME'
              | 'SOA'
              | 'MB'
              | 'MG'
              | 'MR'
              | 'NULL'
              | 'WKS'
              | 'PTR'
              | 'HINFO'
              | 'MINFO'
              | 'MX'
              | 'TXT'
              | 'TSIG'
              | 'AXFR'
              | 'MAILB'
              | 'MAILA'
              | '*'
              | 0..16#ffff
              | <<_:16>>.

-spec encode_type(type()) -> <<_:16>>.

encode_type('A')     -> <<1:16>>;
encode_type('NS')    -> <<2:16>>;
encode_type('MD')    -> <<3:16>>;
encode_type('MF')    -> <<4:16>>;
encode_type('CNAME') -> <<5:16>>;
encode_type('SOA')   -> <<6:16>>;
encode_type('MB')    -> <<7:16>>;
encode_type('MG')    -> <<8:16>>;
encode_type('MR')    -> <<9:16>>;
encode_type('NULL')  -> <<10:16>>;
encode_type('WKS')   -> <<11:16>>;
encode_type('PTR')   -> <<12:16>>;
encode_type('HINFO') -> <<13:16>>;
encode_type('MINFO') -> <<14:16>>;
encode_type('MX')    -> <<15:16>>;
encode_type('TXT')   -> <<16:16>>;
encode_type('TSIG')  -> <<250:16>>;
encode_type('AXFR')  -> <<252:16>>;
encode_type('MAILB') -> <<253:16>>;
encode_type('MAILA') -> <<254:16>>;
encode_type('*')     -> <<255:16>>;
encode_type(B) when is_binary(B) -> B;
encode_type(I) when is_integer(I) -> <<I:16>>.

-type class() :: 'IN'
               | '*'
               | 'NONE'.

-spec encode_class(class()) -> <<_:16>>.

encode_class('IN') -> <<1:16>>;
encode_class('*') -> <<255:16>>;
encode_class('NONE') -> <<254:16>>.

-type question() :: {name(), type(), class()}.

-spec encode_question(question()) -> iodata().

encode_question({Name, Type, Class}) ->
    [encode_name(Name), encode_type(Type), encode_class(Class)].

-type resource_record() :: {name(), type(), class(), 0..16#ffffffff, binary()}.

-spec encode_resource_record(resource_record()) -> iodata().

encode_resource_record({Name, Type, Class, Ttl, Rdata}) ->
    [encode_name(Name),
     encode_type(Type),
     encode_class(Class),
     <<Ttl:32>>,
     <<(byte_size(Rdata)):16>>,
     Rdata].

-spec bool_to_num(boolean()) -> integer().

bool_to_num(false) -> 0;
bool_to_num(true)  -> 1.

-type message() :: {0..16#ffff, boolean(), 0..16#f, boolean(), boolean(), boolean(), boolean(), 0..16#f, [question()], [resource_record()], [resource_record()], [resource_record()]}.

-spec encode_message(message()) -> iodata().

encode_message({QueryId, IsResponse, OpCode, IsAuthorative, IsTruncated,
                IsRecursionDesired, IsRecursionAvailable, Rcode, Questions,
                Answers, Authority, Additional}) ->
    QuestionCount = length(Questions),
    AnswerCount = length(Answers),
    AuthorityCount = length(Authority),
    AdditionalCount = length(Additional),

    [<<QueryId:16>>,

     <<(bool_to_num(IsResponse)):1,
       OpCode:4,
       (bool_to_num(IsAuthorative)):1,
       (bool_to_num(IsTruncated)):1,
       (bool_to_num(IsRecursionDesired)):1,
       (bool_to_num(IsRecursionAvailable)):1,
       0:3,
       Rcode:4>>,

     <<QuestionCount:16,
       AnswerCount:16,
       AuthorityCount:16,
       AdditionalCount:16>>,

     [encode_question(Q) || Q <- Questions],
     [encode_resource_record(Ans) || Ans <- Answers],
     [encode_resource_record(Auth) || Auth <- Authority],
     [encode_resource_record(Addi) || Addi <- Additional]].

-spec get_message_hmac_record(message()) -> resource_record().

get_message_hmac_record(Message) ->
    DnsDigest = encode_message(Message),

    Timepoint = os:system_time(second),
    Fudge = 30,
    OriginalId = 1,
    Error = 0,
    Other = <<>>,
    OtherLen = byte_size(Other),

    TsigDigest = <<
        9:8, "updatekey", 0:8,
        255:16, 0:32,
        11:8, "hmac-sha256", 0:8,
        Timepoint:48, Fudge:16,
        Error:16, OtherLen:16,
        Other/binary>>,

    Digest = [DnsDigest, TsigDigest],

    Mac = crypto:mac(hmac, sha256, <<"1\n">>, Digest),
    MacSize = byte_size(Mac),

    Rdata = <<11:8, "hmac-sha256", 0:8, Timepoint:48, Fudge:16, MacSize:16,
              Mac/binary, OriginalId:16, Error:16, OtherLen:16, Other/binary>>,
    {"updatekey", 'TSIG', '*', 0, Rdata}.

hmac_encode_message({QueryId, IsResponse, OpCode, IsAuthorative, IsTruncated,
                     IsRecursionDesired, IsRecursionAvailable, Rcode, Questions,
                     Answers, Authority, Additional}=Msg) ->
    HmacRR = get_message_hmac_record(Msg),
    encode_message({QueryId, IsResponse, OpCode, IsAuthorative, IsTruncated,
                    IsRecursionDesired, IsRecursionAvailable, Rcode, Questions,
                    Answers, Authority, Additional ++ [HmacRR]}).

-type prerequisite() :: {use, name()}
                      | {exists, name(), type()}
                      | {exists, name(), type(), binary()}
                      | {not_use, name()}
                      | {not_exists, name(), type()}.

-spec prerequisite_to_rr(name(), prerequisite()) -> resource_record().

prerequisite_to_rr(_, {use, Name}) ->
    {Name, '*', '*', 0, <<>>};
prerequisite_to_rr(_, {exists, Name, Type}) ->
    {Name, Type, '*', 0, <<>>};
prerequisite_to_rr(ZoneClass, {exists, Name, Type, Binary}) ->
    {Name, Type, ZoneClass, 0, Binary};
prerequisite_to_rr(_, {not_use, Name}) ->
    {Name, '*', 'NONE', 0, <<>>};
prerequisite_to_rr(_, {not_exists, Name, Type}) ->
    {Name, Type, 'NONE', 0, <<>>}.

create_update_message({QueryId, ZoneName, ZoneClass, Prerequisites, Updates}) ->
    {QueryId, false, 5, false, false, false, false, 0,
     [{ZoneName, 'SOA', ZoneClass}],
     [prerequisite_to_rr(ZoneClass, P) || P <- Prerequisites],
     Updates,
     []}.

main(_) ->
    io:format("Ok~n", []),
    {ok, T} = gen_tcp:connect({127, 0, 0, 1}, 53, [{active, true}, binary, {packet, 2}]),
    QueryId = 1,
    Message = create_update_message(
                {QueryId, "xn--dpping-wxa.eu", 'IN', [{not_exists, "hello-erlang.xn--dpping-wxa.eu", 'A'}],
                 [{"hello-erlang-preq.xn--dpping-wxa.eu", 'A', 'IN', 3600, <<192, 168, 2, 4>>}]}),
    Msg = hmac_encode_message(Message),
    io:format("~p", [Msg]),
    ok = gen_tcp:send(T, [Msg]),
    receive
        N ->
            io:format("~p", [N])
    end,
    gen_tcp:close(T).
