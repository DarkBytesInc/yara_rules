rule Win_Worm_Bagle_244
{
strings:
	$a0 = { e9793c40ad89452da0a423877dbe6e62c9cd04a0a83824abb48656facfd5efc77868fb650952d567a80dc56064a69c3f2ca9e49164e5bf9fd90dd5e18724d10c03587674cd47586b537d80f6ce7866d1f8331a353ea2dc02d930c270cc56e5c5e2a5c10bc6b516ec3915e131c88cdd82346e41c310c64fd1274634f22672d30d02e7ceb23f01c610f2bd414eb2007f4333828755f567 }

condition:
	$a0
}

        