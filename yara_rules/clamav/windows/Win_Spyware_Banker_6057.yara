rule Win_Spyware_Banker_6057
{
strings:
	$a0 = { 9dfd9c2cce0f518b2a39c7d03ba0b854cb9500001c9e7abff651dbe370befe70157049cfa4da95cd5b0a054000104a7d38b1439dfe59688a09a1bab7dacb031b357eb0f14a6893836989c6c5327acd255cfe4e3a2958f631d131c1b452b8d1643917d5c65c5844686494e066dbc18a51d4a06b2a4f6804ee8938ddba69877c152d0383c0422542d8ce74a0e0 }

condition:
	$a0
}

        