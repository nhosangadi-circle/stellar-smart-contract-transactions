package org.example;

import okhttp3.OkHttpClient;
import org.stellar.sdk.*;
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
            Server server = new Server("", getUnsafeOkHttpClient(), getUnsafeOkHttpClient());

            String sourceAccountId = "GAJTZM7UD2CI3WQ356QFX2RGVLNVYWTMQ76DCKPDOTEOXJDFSSWRKPYS";
            String sourceSecretKey = "SDE6L3JVJX647EP2MOHMVDKSIIH6YKXFH3G4IQCCV3NM5JO4ZYM24LFB"; // Replace with actual secret key
            String contractId = "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA"; // SAC contract address
            String toAddress = "CA2BUIM5VDDH6GG3LGOFOLO43ZXQ6PPT2YOTDPR4LKIQF43KEMR666BN"; // Replace with destination address
            BigInteger amount = BigInteger.valueOf(10000000); // Amount in stroops (e.g., 100.0000000 XLM)

            AccountResponse sourceAccount = server.accounts().account(sourceAccountId);
            KeyPair sourceKeyPair = KeyPair.fromSecretSeed(sourceSecretKey);

            System.out.println("Building SAC transfer transaction...");
            System.out.println("Source Account: " + sourceAccountId);
            System.out.println("Contract ID: " + contractId);

            Transaction transaction = buildSacTransferTransaction(
                sourceAccount, 
                sourceKeyPair, 
                contractId, 
                sourceAccountId, 
                toAddress, 
                amount, 
                network
            );

            System.out.println("Transaction built successfully!");
            System.out.println("Transaction XDR: " + transaction.toEnvelopeXdrBase64());
            server.submitTransaction(transaction, true);

        } catch (BadRequestException e) {
            System.err.println("EROROROROROR: " + e.getProblem());
            e.printStackTrace();
        }

        catch (Exception e) {
            System.err.println("Error building transaction: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static Transaction buildSacTransferTransaction(
            AccountResponse sourceAccount,
            KeyPair sourceKeyPair,
            String contractId,
            String fromAddress,
            String toAddress,
            BigInteger amount,
            Network network
    ) throws IOException {

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
        long resourceFee = 109107;


        // Initialize LedgerKeyEntries.
        LedgerKey sacLedgerKey = LedgerKey.builder()
                .discriminant(LedgerEntryType.CONTRACT_DATA)
                .contractData(LedgerKey.LedgerKeyContractData.builder()
                        .contract(Scv.toAddress(contractId).getAddress())
                        .key(SCVal.builder().discriminant(SCValType.SCV_LEDGER_KEY_CONTRACT_INSTANCE).build())
                        .durability(ContractDataDurability.PERSISTENT)
                        .build()).build();

        LedgerKey fromLedgerKey = getLedgerKeyFromAddress(fromAddress, contractId);
        LedgerKey toLedgerKey = getLedgerKeyFromAddress(toAddress, contractId);

        SorobanTransactionData sorobanTransactionData = SorobanTransactionData.builder()
                .resources(SorobanResources.builder()
                        .footprint(LedgerFootprint.builder()
                                .readOnly(new LedgerKey[]{sacLedgerKey})
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
                .build();

        // Build the transaction
        Transaction tx = new TransactionBuilder(sourceAccount, network)
                .addOperation(operation)
                .setTimeout(300)
                .setBaseFee(10000000)
                .setSorobanData(sorobanTransactionData)
                .build(); // 5 minutes timeout

        
        tx.sign(sourceKeyPair);

        System.out.println(sorobanTransactionData.toXdrBase64());

        return tx;
    }

    private static LedgerKey getLedgerKeyFromAddress(String address, String contractId) {
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
                                            .issuer(KeyPair.fromAccountId("GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5").getXdrAccountId())
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
