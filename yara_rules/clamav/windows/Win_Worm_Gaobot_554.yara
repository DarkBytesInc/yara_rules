rule Win_Worm_Gaobot_554
{
strings:
	$a0 = { 51a7c424658508c9cc5f6a948681c441153320ffe6aad2804e190fef692d139ab32c2f8f752ee131fc33f6bdaada2100dc330eb80ba11ae2eb2a01d8c514e8962ea87f6a0a649318d0d97d97813102eba6b63d913be7dfae9776eaa61cdeb969f255280b814e64165b555641543bfb39865da5b06d0bc0ea26300bed4d742a687d7d29b6f5598e5112ba1f7c72225fe7d50df2c65b96 }

condition:
	$a0
}

        