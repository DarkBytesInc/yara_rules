rule Win_Trojan_Small_3846
{
strings:
	$a0 = { 0d62b997cea3a38c02530e100dcda6fef273c83fbd62d9efe1a3a367bf63a37fa53ad8ffbce667188626f75648dfc70ff03edffa3267d5bfa890dc1e3185f98a84ee9affed621824d14b4d3abd63fc847dbc180b4029a84248 }

condition:
	$a0
}

        
