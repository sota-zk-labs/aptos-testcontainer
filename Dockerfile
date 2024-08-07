FROM aptoslabs/tools:mainnet
RUN timeout 20s bash -c "aptos node run-localnet --performance" ||:
COPY contract-sample /contract-sample
RUN cd /contract-sample && aptos move compile ||: && rm -R /contract-sample