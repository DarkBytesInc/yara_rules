rule Win_Trojan_Agent_31502
{
strings:
	$a0 = { 302537a3ceef845afa185ca6b7f81f36be72bc7707bcf30176371f39659d94c001d515fe61f874a7a23c392a7bce99d582434c2bfe954c0fa2f38b4563f9b9406c62d83f49a54ca23abe62c7dbf1630834375a29a42edf29c7c5c5eeb0728f24d6c51c49f9e8a8e09329879e7d2cc1bb3fde361e89e87cdec934762b3816f62a88f5bf1497b2e8dbed38f2fdb855bee68cb8701b85b1 }

condition:
	$a0
}

        