package org.example;

import okhttp3.OkHttpClient;
import org.stellar.sdk.*;
import org.stellar.sdk.FeeBumpTransaction;
import org.stellar.sdk.Transaction;
import org.stellar.sdk.exception.BadRequestException;
import org.stellar.sdk.operations.InvokeHostFunctionOperation;
import org.stellar.sdk.responses.AccountResponse;
import org.stellar.sdk.scval.Scv;
import org.stellar.sdk.xdr.*;
import org.stellar.sdk.xdr.TrustLineAsset;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.math.BigInteger;
import java.util.List;

public class Main {
    public static void main(String[] args) {
        try {
            Network network = Network.TESTNET;
            Server server = new Server("", getUnsafeOkHttpClient(), getUnsafeOkHttpClient()); // Put a quicknode testnet URL here.

            String sourceAccountId = "GAJTZM7UD2CI3WQ356QFX2RGVLNVYWTMQ76DCKPDOTEOXJDFSSWRKPYS";
            String sourceSecretKey = "SDE6L3JVJX647EP2MOHMVDKSIIH6YKXFH3G4IQCCV3NM5JO4ZYM24LFB";

            AccountResponse sourceAccount = server.accounts().account(sourceAccountId);
            KeyPair sourceKeyPair = KeyPair.fromSecretSeed(sourceSecretKey);

            String channelAccountId = "GCUGDRMQQZH6FFST74QN3QWB33WYNSXFBXNZQJYUFTS5QTACKIORZ7TJ";
            String channelSecretKey = "SBOO4KWGCBZGS5SNDVXMWSERCJMRBAKDDYRFTY6H5PID4W3IJZKH2ENL";

            AccountResponse channelAccount = server.accounts().account(channelAccountId);
            KeyPair channelKeyPair = KeyPair.fromSecretSeed(channelSecretKey);

            String contractId = "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA"; // USDC Testnet SAC contract address
            String toAddress = "CBKN4YDEGJW5NF7HAPXIPGKPZWGXP7ABGN6WLAJWE4OA2CN56GKYFCAH";
            BigInteger amount = BigInteger.valueOf(10000000); // Amount in stroops (1 lumen -> 10^7 stroops)

            String issuer = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5";

            System.out.println("Building SAC transfer transaction...");
            System.out.println("Source Account: " + sourceAccountId);
            System.out.println("Contract ID: " + contractId);

            // Normal transaction initiated by source account.
            String transaction = buildSacTransferTransaction(
                sourceAccount, 
                sourceKeyPair,
                contractId,
                toAddress, 
                amount, 
                network,
                issuer
            );

            System.out.println("Transaction built successfully!");
            System.out.println("Transaction XDR: " + transaction);
            server.submitTransactionXdr(transaction);

            // Channel account transaction using fee bump tx.
            String channelTransaction = buildSacTransferTransaction(
                    sourceAccount,
                    sourceKeyPair,
                    channelAccount,
                    channelKeyPair,
                    contractId,
                    toAddress,
                    amount,
                    network,
                    issuer
            );

            System.out.println("Transaction built successfully!");
            System.out.println("Transaction XDR: " + channelTransaction);
            server.submitTransactionXdr(channelTransaction);

        } catch (BadRequestException e) {
            System.err.println("Error: " + e.getProblem());
            e.printStackTrace();
        }

        catch (Exception e) {
            System.err.println("Error building transaction: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static String buildSacTransferTransaction(
            AccountResponse sourceAccount,
            KeyPair sourceKeyPair,
            String contractId,
            String toAddress,
            BigInteger amount,
            Network network,
            String issuer
    ) throws IOException {
        return buildSacTransferTransaction(
                sourceAccount,
                sourceKeyPair,
                null,
                null,
                contractId,
                toAddress,
                amount,
                network,
                issuer
        );
    }

    private static String buildSacTransferTransaction(
            AccountResponse sourceAccount,
            KeyPair sourceKeyPair,
            AccountResponse channelAccount,
            KeyPair channelKeyPair,
            String contractId,
            String toAddress,
            BigInteger amount,
            Network network,
            String issuer
    ) throws IOException {

        String fromAddress = sourceAccount.getAccountId();
        // Create the transfer function arguments
        SCVal fromVal = Scv.toAddress(fromAddress);

        SCVal toVal = Scv.toAddress(toAddress);

        SCVal amountVal = Scv.toInt128(amount);

        // Build the invoke contract args for transfer function
        InvokeContractArgs invokeArgs = InvokeContractArgs.builder()
                .contractAddress(Scv.toAddress(contractId).getAddress())
                .functionName(Scv.toSymbol("transfer").getSym())
                .args(new SCVal[]{fromVal, toVal, amountVal})
                .build();


        // Build sourceAuthEntry.
        SorobanAuthorizationEntry authorizationEntry = SorobanAuthorizationEntry.builder()
                .credentials(SorobanCredentials.builder().discriminant(SorobanCredentialsType.SOROBAN_CREDENTIALS_SOURCE_ACCOUNT).build())
                .rootInvocation(SorobanAuthorizedInvocation.builder()
                        .subInvocations(new SorobanAuthorizedInvocation[] {})
                        .function(SorobanAuthorizedFunction.builder()
                                .discriminant(SorobanAuthorizedFunctionType.SOROBAN_AUTHORIZED_FUNCTION_TYPE_CONTRACT_FN)
                                .contractFn(invokeArgs).build()).build()).build();


        // Build Soroban data.

        // Fixed resource values for this example
        // based on the average SAC transfer
        long cpuInstructions = 285237;
        long readBytes = 288;
        long writeBytes = 368;
        long resourceFee = 300000;


        // Initialize LedgerKeyEntries.

        // Read only entries.
        LedgerKey sacLedgerKey = LedgerKey.builder()
                .discriminant(LedgerEntryType.CONTRACT_DATA)
                .contractData(LedgerKey.LedgerKeyContractData.builder()
                        .contract(Scv.toAddress(contractId).getAddress())
                        .key(SCVal.builder().discriminant(SCValType.SCV_LEDGER_KEY_CONTRACT_INSTANCE).build())
                        .durability(ContractDataDurability.PERSISTENT)
                        .build()).build();

        LedgerKey issuerLedgerKey = LedgerKey.builder()
                .discriminant(LedgerEntryType.ACCOUNT)
                .account(LedgerKey.LedgerKeyAccount.builder()
                        .accountID(KeyPair.fromAccountId(issuer).getXdrAccountId())
                        .build())
                .build();

        // Read-Write entries.
        LedgerKey fromLedgerKey = getLedgerKeyFromAddress(fromAddress, contractId, issuer);
        LedgerKey toLedgerKey = getLedgerKeyFromAddress(toAddress, contractId, issuer);

        SorobanTransactionData sorobanTransactionData = SorobanTransactionData.builder()
                .resources(SorobanResources.builder()
                        .footprint(LedgerFootprint.builder()
                                .readOnly(new LedgerKey[]{sacLedgerKey, issuerLedgerKey})
                                .readWrite(new LedgerKey[]{fromLedgerKey, toLedgerKey})
                                .build())
                        .instructions(Scv.toUint32(cpuInstructions).getU32())
                        .diskReadBytes(Scv.toUint32(readBytes).getU32())
                        .writeBytes(Scv.toUint32(writeBytes).getU32())
                        .build())
                .resourceFee(Scv.toInt64(resourceFee).getI64())
                .ext(SorobanTransactionData.SorobanTransactionDataExt.builder()
                        .discriminant(0)
                        .build())
                .build();



        HostFunction hostFunction = HostFunction.builder()
                .discriminant(HostFunctionType.HOST_FUNCTION_TYPE_INVOKE_CONTRACT)
                .invokeContract(invokeArgs)
                .build();

        // Create the invoke host function operation
        InvokeHostFunctionOperation operation = InvokeHostFunctionOperation.builder()
                .hostFunction(hostFunction)
                .auth(List.of(authorizationEntry))
                .sourceAccount(fromAddress)
                .build();

        if (channelAccount == null) {

            // Build the transaction
            Transaction tx = new TransactionBuilder(sourceAccount, network)
                    .addOperation(operation)
                    .setTimeout(300)
                    .setBaseFee(10000000)
                    .setSorobanData(sorobanTransactionData)
                    .build(); // 5 minutes timeout


            tx.sign(sourceKeyPair);

            return tx.toEnvelopeXdrBase64();
        }
        else {
            // Build the transaction
            Transaction tx = new TransactionBuilder(channelAccount, network)
                    .addOperation(operation)
                    .setTimeout(300)
                    .setBaseFee(10000000)
                    .setSorobanData(sorobanTransactionData)
                    .build(); // 5 minutes timeout


            tx.sign(channelKeyPair);
            tx.sign(sourceKeyPair);

            FeeBumpTransaction feeBumpTransaction = FeeBumpTransaction.createWithBaseFee(fromAddress, tx.getFee(), tx);
            feeBumpTransaction.sign(sourceKeyPair);

            return feeBumpTransaction.toEnvelopeXdrBase64();
        }
    }

    private static LedgerKey getLedgerKeyFromAddress(String address, String contractId, String issuer) {
        if (StrKey.isValidEd25519PublicKey(address)) {
            AssetCode4 usdcCode = new AssetCode4();
            usdcCode.setAssetCode4(Util.paddedByteArray("USDC", 4));
            return LedgerKey.builder()
                    .discriminant(LedgerEntryType.TRUSTLINE)
                    .trustLine(LedgerKey.LedgerKeyTrustLine.builder()
                            .accountID(KeyPair.fromAccountId(address).getXdrAccountId())
                            .asset(TrustLineAsset.builder()
                                    .discriminant(AssetType.ASSET_TYPE_CREDIT_ALPHANUM4)
                                    .alphaNum4(AlphaNum4.builder()
                                            .assetCode(usdcCode)
                                            .issuer(KeyPair.fromAccountId(issuer).getXdrAccountId())
                                            .build())
                                    .build())
                            .build())
                    .build();
        }
        else if(StrKey.isValidContract(address)) {
            return LedgerKey.builder()
                    .discriminant(LedgerEntryType.CONTRACT_DATA)
                    .contractData(LedgerKey.LedgerKeyContractData.builder()
                            .contract(Scv.toAddress(contractId).getAddress())
                            .key(Scv.toVec(List.of(Scv.toSymbol("Balance"), Scv.toAddress(address))))
                            .durability(ContractDataDurability.PERSISTENT)
                            .build()).build();
        }
        return null;
    }

    private static OkHttpClient getUnsafeOkHttpClient() {
        try {
            final TrustManager[] trustAllCerts = new TrustManager[]{
                    new X509TrustManager() {
                        public void checkClientTrusted(X509Certificate[] chain, String authType) {
                        }

                        public void checkServerTrusted(X509Certificate[] chain, String authType) {
                        }

                        public X509Certificate[] getAcceptedIssuers() {
                            return new X509Certificate[]{};
                        }
                    }
            };

            SSLContext sslContext = SSLContext.getInstance("SSL");
            sslContext.init(null, trustAllCerts, new java.security.SecureRandom());

            return new OkHttpClient.Builder()
                    .sslSocketFactory(sslContext.getSocketFactory(), (X509TrustManager) trustAllCerts[0])
                    .hostnameVerifier((hostname, session) -> true)
                    .build();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
