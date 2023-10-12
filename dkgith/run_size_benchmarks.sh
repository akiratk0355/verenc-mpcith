#!/usr/bin/bash

echo "------------------------------------";
echo "Printing sizes for DKGitH instances:";
echo "------------------------------------";
cargo test --release -- --exact --nocapture dkgith::tests::test_ve_print_sizes;

echo "------------------------------------";
echo "Printing sizes for RDKGitH instances:";
echo "------------------------------------";
cargo test --release -- --exact --nocapture rdkgith::tests::test_ve_print_sizes;

echo "------------------------------------";
echo "Printing sizes for CD00 instances:";
echo "------------------------------------";
cargo test --release -- --exact --nocapture camdam::tests::test_ve_print_sizes;

