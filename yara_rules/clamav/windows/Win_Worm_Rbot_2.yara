rule Win_Worm_Rbot_2
{
strings:
	$a0 = { 306dbb5db6af20257b1c377ca91ffd5bcdc072ff16a033c1017fa7464a34d1119ffef38004b8859a8f0800ea5112a5ca054e94007e }

condition:
	$a0
}

        
