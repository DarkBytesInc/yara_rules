rule Win_Trojan_FakeAV_185
{
strings:
	$a0 = { ba48f5ffff558bec81eca0010000e8000000005881c2a333400081ea903340002bc2898560feffff8bb560feffffb9650000008dbd68fefffff3a5ffb580feffff58ff308f85f0feffffffb584feffff58ff308f85f4fefffffc8b8de4feffff8bb5dcfeffff8bfe03bde0fefffff3a46a008b85d4feffff508b95c8feffff8b }

condition:
	$a0
}

        
