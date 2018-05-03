rule Win_Proxy_Small_4657
{
strings:
	$a0 = { 21450c837d0c007411a13067001085c07408575653ffd089450c8b450c5f5e5b5dc20c00ff2590300010 }

condition:
	$a0
}

        
