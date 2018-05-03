rule Win_Worm_Rbot_5
{
strings:
	$a0 = { c0b3f56947092d2ef2e0806a6215dc3950b149c7c0ca2d61f9a0eb213f91ae2376421ae392460d8bd71a9c3f78ec2159b4292a400ca62347baa8ee132cb89ecd6f166b5db56ad4a9ac20e9b531ed1d3c81d809ff7fafdd9661e3f89747cefa4c }

condition:
	$a0
}

        
