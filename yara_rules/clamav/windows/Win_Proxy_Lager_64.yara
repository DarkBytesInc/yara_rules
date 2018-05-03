rule Win_Proxy_Lager_64
{
strings:
	$a0 = { 0fa88f2486e84964fee689535567475a0febcc790b3becce65df21521f9070726b3c6c7409331adcf130709ca3a2f344ee20947126e0ca7c084bcc797622f0766e5533ab4a5e }

condition:
	$a0
}

        
