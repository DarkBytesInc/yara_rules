rule Win_Trojan_SdBot_45
{
strings:
	$a0 = { 640c3508819d666559144795da088e6379118469657708a6ab48583c2878f183586d9606d6095cf170f9678aa968790c5211186de74008086b9099bb58220c890867c64608a692d2110a197308426e61306d658c786743722c6624126e49146827de64a9334ce537548b2acd97b4105ac44a10506578ff0de3d49612a1d642343c2708086f6872c23132e1225477187da6081c544553 }

condition:
	$a0
}

        