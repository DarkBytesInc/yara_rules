rule Win_Trojan_SdBot_2035
{
strings:
	$a0 = { 955955afb8f5c9afb8feeffef1cf2bce8ef6bcffed7eae0dd5cfb8cd4774404eeaba25d9d06a6d62219b36a9a3b5856e61d233e2aba40af2bbd35f61e8ac43d6d35683eb118e7815df6b05593e3fc0e0e42c8beee4f96c64e6af8e91c8191a9c32be7c2da67f768b9dbb829791aafa8a9cd5bb289f7320ca6fd03c2b95b96ed02d3b394cdb0ef77020c6f11a }

condition:
	$a0
}

        