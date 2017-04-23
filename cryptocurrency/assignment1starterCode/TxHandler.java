import java.security.PublicKey;
import java.util.ArrayList;

public class TxHandler {

    /**
     * Creates a public ledger whose current UTXOPool (collection of unspent transaction outputs) is
     * {@code utxoPool}. This should make a copy of utxoPool by using the UTXOPool(UTXOPool uPool)
     * constructor.
     */
    private UTXOPool utxopool;
    public TxHandler(UTXOPool utxoPool) {
        this.utxopool = utxopool;
    }

    /**
     * @return true if:
     * (1) all outputs claimed by {@code tx} are in the current UTXO pool, 
     * (2) the signatures on each input of {@code tx} are valid, 
     * (3) no UTXO is claimed multiple times by {@code tx},
     * (4) all of {@code tx}s output values are non-negative, and
     * (5) the sum of {@code tx}s input values is greater than or equal to the sum of its output
     *     values; and false otherwise.
     */
    public boolean isValidTx(Transaction tx) {
        // Transaction.Input = all the coins that go into a transaction
        // Transaction.Output = all the coins that come out of a transaction
        // In a transaction, you consume UTXO and then output some UTXOs as a result
        // Inputs - you must know the private key because you're the owner
        // Outputs - you must know the public key (address) of each recipient
        byte[] txHash = tx.getHash();
        ArrayList<UTXO> allUtxo = this.utxopool.getAllUTXO();
        ArrayList<UTXO> checkedUtxos = new UTXOPool;
        double outputSum = 0;
        double inputSum = 0;
        // Checks (1), (2), (3)
        for (int i=0; i < tx.numInputs(); i++) {
            Transaction.Input input = tx.getInput(i);
            byte[] prevHash = input.prevTxHash;
            UTXO utxo = new UTXO(prevHash, input.outputIndex);
            if (!this.utxopool.contains(utxo)) return false;
            Transaction.Output output = utxopool.getTxOutput(utxo);
            if (!Crypto.verifySignature(output.address, tx.getRawDataToSign(input.outputIndex), input.signature)) return false;
            if (checkedUtxos.contains(utxo)) return false;
            checkedUtxos.add(utxo);
            inputSum += output.value;
        }
        // Checks (4)
        for (int i=0; i < tx.numOutputs(); i++) {
            Transaction.Output output = tx.getOutput(i);
            if (output.value < 0) return false;
            outputSum += output.value;
        }
        // Checks (5)
        return (inputSum >= outputSum);
    }

    /**
     * Handles each epoch by receiving an unordered array of proposed transactions, checking each
     * transaction for correctness, returning a mutually valid array of accepted transactions, and
     * updating the current UTXO pool as appropriate.
     */
    public Transaction[] handleTxs(Transaction[] possibleTxs) {
        ArrayList<Transaction> validTxs = new ArrayList;
        for (int i=0; i < possibleTxs.length; i++) {
            Transaction tx = possibleTxs[i];
            if (isValidTx(tx)) validTxs.add(tx);
            for (int j=0; j < tx.numInputs(); j++) {
                Transaction.Input input = tx.getInput(j);
                UTXO utxo = new UTXO(input.prevTxHash, input.outputIndex);
                this.utxopool.removeUTXO(utxo);
            }
            for (int j=0; j < tx.numOutputs(); j++) {
                Transaction.Output output = tx.getOutput(j);
                UTXO utxo = new UTXO(tx.getHash(), j);
                this.utxopool.addUTXO(utxo, output);
            }
        }
        Transaction[] validTxArray = new Transaction[validTxs.size()];
        return validTxs.toArray(validTxArray);
    }
}
