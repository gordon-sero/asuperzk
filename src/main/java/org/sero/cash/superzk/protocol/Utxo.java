package org.sero.cash.superzk.protocol;

import java.util.List;

import org.sero.cash.superzk.protocol.czero.Czero;
import org.sero.cash.superzk.protocol.superzk.SuperZk;

import com.google.common.collect.Lists;

public class Utxo {
    public AccountType.PKr Pkr;
    public byte[] Root;
    public List<byte[]> Nils;
    public byte[] TxHash;
    public long Num;
    public Types.Asset Asset;
    public boolean IsZ;
    public byte[] Memo;
    public Types.RootState State;


    public static List<Utxo> decOut(AccountType.TK tk, List<Types.Out> outs) {
        List<Utxo> result = Lists.newArrayList();
        outs.forEach(out -> {
            AccountType.PKr pkr = null;
            boolean isZ = false;
            Types.TDOut dout = new Types.TDOut();
            dout.Nils = Lists.newArrayList();
            Types.OutState os = out.State.OS;
            if (os.Out_O != null) {
                dout.Asset = os.Out_O.Asset;
                dout.Memo = os.Out_O.Memo;
                dout.Nils.add(out.Root);
                dout.Nils.add(Czero.genTrace(tk, os.RootCM).toBytes());
                pkr = os.Out_O.Addr;
            } else if (os.Out_Z != null) {

                byte[] key = Czero.fetchKey(tk, os.Out_Z.RPK);
               
                Types.TDOut comfirm_out = Czero.confirmOutZ(
                        key,
                        os.Out_Z.EInfo,
                        os.Out_Z.PKr,
                        os.Out_Z.OutCM
                );
                if (comfirm_out != null) {
                    dout.Asset = comfirm_out.Asset;
                    dout.Memo = comfirm_out.Memo;
                    dout.Nils.add(Czero.genTrace(tk, os.RootCM).toBytes());
                    pkr = os.Out_Z.PKr;
                    isZ = true;
                }
            } else if (os.Out_P != null) {
                dout.Asset = os.Out_P.Asset;
                dout.Memo = os.Out_P.Memo;
                dout.Nils.add(SuperZk.genNil(tk, os.RootCM, os.Out_P.PKr));
                pkr = os.Out_P.PKr;
            } else if (os.Out_C != null) {
                Types.TDOut comfirm_out = SuperZk.confirmOutC(SuperZk.fetchRPKKey(os.Out_C.PKr, tk, os.Out_C.RPK), os.Out_C.EInfo, os.Out_C.AssetCM);
                if (comfirm_out != null) {
                    dout.Asset = comfirm_out.Asset;
                    dout.Memo = comfirm_out.Memo;
                    dout.Nils.add(SuperZk.genNil(tk, os.RootCM, os.Out_C.PKr));
                    pkr = os.Out_C.PKr;
                    isZ = true;
                }
            } else {
                throw new Error("invalid out type");
            }

            if (pkr != null) {
                // @ts-ignore
                Utxo utxo = new Utxo();
                utxo.Root = out.Root;
                utxo.State = out.State;
                utxo.Pkr = pkr;
                utxo.Asset = dout.Asset;
                utxo.Num = out.State.Num;
                utxo.Memo = dout.Memo;
                utxo.Nils = dout.Nils;
                utxo.IsZ = isZ;
                utxo.TxHash = out.State.TxHash;
                result.add(utxo);
            }
        });
		return result;
	}
}
