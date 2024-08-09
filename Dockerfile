FROM aptoslabs/tools:mainnet
ENV ROOT_ACCOUNT_PRIVATE_KEY="0x3c05744aad754b4a62563370f1a5d49b16c80d0fb395a20ee8439a67fe1361bf"
RUN timeout 40s bash -c "aptos node run-localnet --performance & \
    ( \
      sleep 22 && \
      (echo $ROOT_ACCOUNT_PRIVATE_KEY  \
        | aptos init --network local --assume-yes) && \
      aptos account fund-with-faucet && \
      aptos account fund-with-faucet && \
      aptos account fund-with-faucet && \
      aptos account fund-with-faucet && \
      aptos account fund-with-faucet \
    )"

COPY contract-sample /contract-sample
RUN cd /contract-sample && aptos move compile ||:
RUN rm -R /contract-sample