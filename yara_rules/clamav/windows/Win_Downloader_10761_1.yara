rule Win_Downloader_10761_1
{
strings:
	$a0 = { 7db4eb09c0ff5ca913cf1b3416f0942bcea1c9909006ac33a02c8c146e9c01cd48757831fb3b647505866ee0eb0379b70c0a349863390c72b90416a0d16da4870a60070f8601c7ffe9736b797221bb345212c8427a06463c40b14077eefe07c8780deb15c704674ee17ce96d4227dec146c0e9f623220adcf7dad6048a043187d8017c0302e01a88f6191441423b9b30 }

condition:
	$a0
}

        