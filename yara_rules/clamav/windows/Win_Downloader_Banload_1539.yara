rule Win_Downloader_Banload_1539
{
strings:
	$a0 = { 8dfff8f8f8fffffaf3fffff9f3fffff9f3fffff9f3fffff9f3fffff9f2ffefe7dbffdbcab0ffc5a97cffbc9658ffb8904effaf8f63ffd2c2aefffff9f3fffef9f2ff9b6a69ff9b6a69ff9b6a69ff9b6a69ff9b6a69ff9b6a69ff0000003b0000000b000000000000000000 }

condition:
	$a0
}

        
