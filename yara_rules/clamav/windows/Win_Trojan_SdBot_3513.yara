rule Win_Trojan_SdBot_3513
{
strings:
	$a0 = { 36db5b8db6db62e3771b971adc6dc971b6dcb8dcb8db6e5c985798b39d9ff67ddbccff9ff1ff35ac1fe7b555ed5463747c88edbfc5648220bd916a88f57acf1e56fa3922e7a81a5332ffb026a6e7e6b7b1d72d5e429d0919e404d57ed8adf5c0c98399f5677f88434cf255e93af27e9dd68b702bbf3dc73a7da0db3fd3 }

condition:
	$a0
}

        
