rule Win_Trojan_Pakes_36
{
strings:
	$a0 = { 78c5d822f27a73cef6df22cf0d1c73719cd046d8f1c6c0ca99bb57a37ebe46c990f1c6d7e10f86ba934878dbad8bd3d224dbf11ab542c7d5dc9b9598fe81ff182b1c3bb817781e5bfc4d5dd0f1552c1483415faca074c1ffcaec0f2aef8606f8e2430cd59ffc8d86fe17e1cbea46b11b82a695ddb7309e6da3dcd8f20012455d }

condition:
	$a0
}

        
