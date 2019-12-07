package org.sero.cash.superzk.protocol;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.sero.cash.superzk.protocol.superzk.Account;
import org.sero.cash.superzk.util.Arrays;
import org.sero.cash.superzk.util.HexUtils;

public class Transaction {


    public interface TxParamGenerator {
        List<Types.Utxo> findUtxos(AccountType.PKr accountKey, String currency, BigInteger amount);

        List<Types.Utxo> findUtxos(AccountType.PKr accountKey, Map<byte[], String> ticket);

        String defaultRefundTo(String accountKey);
    }

    public interface TxParamState {
        List<Types.Witness> getAnchor(List<String> roots);
    }


    private static class CmdClazz extends Types.Cmds {
        public Types.ContractCmd Contract;

        CmdClazz(Types.Cmds cmds) {
            this.Contract = cmds.Contract;
        }

        public Types.Asset outAsset() {
            if (this.Contract != null) {
                return this.Contract.Asset;
            }
            return null;
        }
    }

    public static Types.GTxParam genTxParam(Types.PreTxParam preTxParam, TxParamGenerator gen, TxParamState state) {
        if (preTxParam.Receptions != null && preTxParam.Receptions.size() > 500) {
            throw new RuntimeException("receptions count must <= 500");
        }
        List<Types.Utxo> utxos = selectUtxos(preTxParam, gen);

//        if (StringUtils.isEmpty(preTxParam.RefundTo)) {
//            preTxParam.RefundTo = gen.defaultRefundTo(preTxParam.From);
//            if (StringUtils.isEmpty(preTxParam.RefundTo)) {
//                throw new RuntimeException("can not find default refund to");
//            }
//        }
        Types.BeforeTxParam bparam = new Types.BeforeTxParam(preTxParam.Fee, preTxParam.GasPrice, utxos, preTxParam.RefundTo, preTxParam.Receptions, preTxParam.Cmds);
        return buildTxParam(state, bparam);
    }

    private static Types.GTxParam buildTxParam(TxParamState state, Types.BeforeTxParam param) {
        List<String> roots = new ArrayList<String>();
        param.Utxos.forEach(u -> {
            roots.add(HexUtils.toHex(u.Root));
        });
        List<Types.Witness> wits = state.getAnchor(roots);
        if (wits == null || wits.size() == 0) {
            throw new RuntimeException("can not find Anchor by root");
        }

        List<Types.GIn> ins = new ArrayList<Types.GIn>();
        int count = 0;
        CKState ck = new CKState(false, param.Fee);
        for (int i = 0; i < param.Utxos.size(); i++) {
            Types.Utxo utxo = param.Utxos.get(i);
            if (utxo.State == null) {
                throw new RuntimeException("can not find out by root");
            }
            ck.AddIn(utxo.Asset);
            ins.add(new Types.GIn(new Types.Out(utxo.Root, utxo.State), wits.get(i)));
            if (utxo.State.OS.Out_O != null) {
                count++;
            }
        }
        if (count > 2500) {
            throw new Error("o_ins count > 2500");
        }
        List<Types.GOut> outs = new ArrayList<Types.GOut>();
        param.Receptions.forEach(r -> {
            ck.AddOut(r.Asset);
            outs.add(new Types.GOut(r.Addr, r.Asset, new byte[64]));
        });
        if (param.Cmds != null) {
            Types.Asset cmdsAsset = new CmdClazz(param.Cmds).outAsset();
            if (cmdsAsset != null) {
                ck.AddOut(cmdsAsset);
            }
        }
        List<Types.Token> tkns = ck.getTknList();
        List<Types.Ticket> tkts = ck.getTktList();

        int maxlen = Math.max(tkns.size(), tkts.size());
        for (int i = 0; i < maxlen; i++) {
            // @ts-ignore
            Types.Asset a = new Types.Asset();
            if (i < tkns.size()) {
                a.Tkn = tkns.get(i);
            }
            if (i < tkts.size()) {
                a.Tkt = tkts.get(i);
            }
            ck.AddOut(a);
            outs.add(new Types.GOut(param.RefundTo, a, new byte[64]));
        }
        ck.checkTicket();
        ck.checkToken();

        Types.GTxParam txParam = new Types.GTxParam(param.Fee, param.GasPrice, new Types.Kr(param.RefundTo));
        txParam.Ins = ins;
        txParam.Outs = outs;

        if (param.Cmds != null) {
            txParam.Cmds = new Types.Cmds(param.Cmds.Contract);
        }
        txParam.Z = false;
        return txParam;
    }

    public static List<Types.Utxo> selectUtxos(Types.PreTxParam param, TxParamGenerator generator) {
        CKState ck = new CKState(true, param.Fee);
        if (param.Cmds != null) {
            Types.Asset cmdAsset = new CmdClazz(param.Cmds).outAsset();
            if (cmdAsset != null) {
                ck.AddOut(cmdAsset);
            }
        }

        param.Receptions.forEach((r) -> {
            ck.AddOut(r.Asset);
        });

        List<Types.Utxo> utxos = new ArrayList<Types.Utxo>();
        if (ck.tk.size() > 0) {
            List<Types.Utxo> list = generator.findUtxos(param.From, ck.tk);
            if (list != null && ck.tk.size() == 0) {
                utxos.addAll(list);
                list.forEach((o) -> {
                    ck.AddIn(o.Asset);
                });
            } else {
                throw new RuntimeException("no enough unlocked utxos");
            }
        }

        ck.cy.state.forEach((key, value) -> {
            List<Types.Utxo> list = generator.findUtxos(param.From, key, value);
            if (list != null && list.size() > 0 && value.signum() <= 0) {
                utxos.addAll(list);
            } else {
                throw new RuntimeException("no enough unlocked utxos");
            }
        });
        return utxos;
    }


    public static Types.GTx signTx(Account.SK sk, Types.GTxParam paramTx) {
        paramTx.From.SKr = sk;
        for (int i = 0; i < paramTx.Ins.size(); i++) {
            paramTx.Ins.get(i).SKr = sk;
        }
//        return SignTx(paramTx);
        return null;
    }

    private static class TokenStateMap {
        Map<String, BigInteger> state = new HashMap<String, BigInteger>();

        public void add(String key, BigInteger value) {
            BigInteger v = this.state.get(key);
            if (v != null) {
                this.state.put(key, v.add(value));
            } else {
                this.state.put(key, value);
            }
        }

        public void sub(String key, BigInteger value) {
            BigInteger v = this.state.get(key);
            if (v != null) {
                this.state.put(key, v.subtract(value));
            } else {
                this.state.put(key, BigInteger.ZERO.subtract(value));
            }
        }
    }

    private static class CKState {
        boolean outPlus;
        TokenStateMap cy;
        Map<byte[], String> tk;

        public CKState(boolean outPlus, Types.Token fee) {
            this.outPlus = outPlus;
            this.cy = new TokenStateMap();
            if (outPlus) {
                this.cy.add(Arrays.byte32ToString(fee.Currency), fee.Value);
            } else {
                this.cy.sub(Arrays.byte32ToString(fee.Currency), fee.Value);
            }
            this.tk = new HashMap<byte[], String>();
        }

        public void AddOut(Types.Asset asset) {
            if (asset.Tkn != null) {
                if (this.outPlus) {
                    this.cy.add(Arrays.byte32ToString(asset.Tkn.Currency), asset.Tkn.Value);
                } else {
                    this.cy.sub(Arrays.byte32ToString(asset.Tkn.Currency), asset.Tkn.Value);
                }
            }

            if (asset.Tkt != null && asset.Tkt.Value != null) {
                if (Arrays.toBigInteger(asset.Tkt.Value).compareTo(BigInteger.valueOf(9)) > 0) {
                    if (this.tk.get(asset.Tkt.Value) != null) {
                        if (this.outPlus) {
                            throw new RuntimeException("out tkt duplicate: " + asset.Tkt.Value);
                        } else {
                            this.tk.remove(asset.Tkt.Value);
                        }
                    } else {
                        if (this.outPlus) {
                            this.tk.put(asset.Tkt.Value, Arrays.byte32ToString(asset.Tkt.Category));
                        } else {
                            throw new RuntimeException("out tkt not in ins : " + asset.Tkt.Value);
                        }
                    }
                }
            }
        }

        public void AddIn(Types.Asset asset) {
            if (asset.Tkn != null) {
                if (!this.outPlus) {
                    this.cy.add(Arrays.byte32ToString(asset.Tkn.Currency), asset.Tkn.Value);
                } else {
                    this.cy.sub(Arrays.byte32ToString(asset.Tkn.Currency), asset.Tkn.Value);
                }
            }

            if (asset.Tkt != null && asset.Tkt.Value != null) {
                if (Arrays.toBigInteger(asset.Tkt.Value).compareTo(BigInteger.valueOf(9)) > 0) {
                    if (this.tk.get(asset.Tkt.Value) != null) {
                        if (!this.outPlus) {
                            throw new RuntimeException("ins tkt duplicate: " + asset.Tkt.Value);
                        } else {
                            this.tk.remove(asset.Tkt.Value);
                        }
                    } else {
                        if (!this.outPlus) {
                            this.tk.put(asset.Tkt.Value, Arrays.byte32ToString(asset.Tkt.Category));
                        } else {
                            throw new RuntimeException("ins tkt not in ins : " + asset.Tkt.Value);
                        }
                    }
                }
            }
        }

        public List<Types.Token> getTknList() {
            List<Types.Token> result = new ArrayList<Types.Token>();
            this.cy.state.forEach((k, v) -> {
                if (v.signum() > 0) {
                    result.add(new Types.Token(Arrays.stringToByte32(k), v));
                }
            });
            return result;
        }

        public List<Types.Ticket> getTktList() {
            List<Types.Ticket> result = new ArrayList<Types.Ticket>();
            this.tk.forEach((v, k) -> {
                result.add(new Types.Ticket(Arrays.stringToByte32(k), v));
            });
            return result;
        }

        public void checkToken() {
            this.cy.state.forEach((k, v) -> {
                if (v.signum() > 0) {
                    throw new RuntimeException("currency " + k + " banlance != 0");
                }
            });
        }

        public void checkTicket() {
            if (this.tk.size() > 0) {
                throw new RuntimeException("ticket not used");
            }
        }
    }

}
