rule Win_Downloader_Banload_467
{
strings:
	$a0 = { d19bc859a037c86131c5095f86835c0239608ddbb641efbed188fd271312ea4468ab9a5c8ac6759864788e21410839e55102574c594cf3110ef3dcb94c131ff7dfea838abdb20fe6b2eeff5996694d6cf30c94d0 }

condition:
	$a0
}

        
