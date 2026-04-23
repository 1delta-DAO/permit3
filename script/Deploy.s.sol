// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script} from "forge-std/Script.sol";
import {Permit3} from "../src/permit3/Permit3.sol";

contract DeployScript is Script {
    function run() public returns (Permit3) {
        vm.startBroadcast();
        Permit3 permit3 = new Permit3();
        vm.stopBroadcast();
        return permit3;
    }
}
