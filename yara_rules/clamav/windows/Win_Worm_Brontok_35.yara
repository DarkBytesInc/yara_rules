rule Win_Worm_Brontok_35
{
strings:
	$a0 = { 8eecb8b0c9a672d12dd73e726d5a39892e55f8dc28f0ed6815399ab87afb9eb3aca1c80c21f69cceb74dd77f9c025baf53c0685152ea88175a3ab9cf3e9e7080b82a2fc110669c065ac1675da4878f0b5480b0ae41a7467a383911ded83b8cea12ffc9ae20ca12d5df3545b1e6a9 }

condition:
	$a0
}

        
