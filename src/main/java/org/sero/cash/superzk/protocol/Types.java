package org.sero.cash.superzk.protocol;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.collections4.CollectionUtils;
import org.ethereum.crypto.HashUtil;
import org.sero.cash.superzk.crypto.ecc.Field;
import org.sero.cash.superzk.crypto.ecc.Point;
import org.sero.cash.superzk.util.Arrays;
import org.spongycastle.util.encoders.Hex;

import com.google.common.collect.Lists;

public class Types {

	public static class Params {
		public List<Point> zin_acms;
		public List<Field.FR> zin_ars;
		public List<Point> zout_acms;
		public List<Field.FR> zout_ars;
		public List<Point> oin_accs;
		public List<Point> oout_accs;

		public Params() {
			zin_acms = Lists.newArrayList();
			zin_ars = Lists.newArrayList();
			zout_acms = Lists.newArrayList();
			zout_ars = Lists.newArrayList();
			oin_accs = Lists.newArrayList();
			oout_accs = Lists.newArrayList();
		}

		public Params(List<Point> zin_acms, List<Field.FR> zin_ars, List<Point> zout_acms, List<Field.FR> zout_ars,
				List<Point> oin_accs, List<Point> oout_accs) {
			this.zin_acms = zin_acms;
			this.zin_ars = zin_ars;
			this.zout_acms = zout_acms;
			this.zout_ars = zout_ars;
			this.oin_accs = oin_accs;
			this.oout_accs = oout_accs;
		}
	}

	public static class Utxo {
		public byte[] Root;
		public Asset Asset;
		public RootState State;
	}

	public static class BeforeTxParam {
		public Token Fee;
		public BigInteger GasPrice;
		public List<Utxo> Utxos;
		public AccountType.PKr RefundTo;
		public List<Reception> Receptions;
		public Cmds Cmds;

		public BeforeTxParam() {
		}

		public BeforeTxParam(Token fee, BigInteger gasPrice, List<Utxo> utxos, AccountType.PKr refundTo,
				List<Reception> receptions, Types.Cmds cmds) {
			Fee = fee;
			GasPrice = gasPrice;
			Utxos = utxos;
			RefundTo = refundTo;
			Receptions = receptions;
			Cmds = cmds;
		}
	}

	public static class Kr {
		public AccountType.SK SKr;
		public AccountType.PKr PKr;

		public Kr() {
		}

		public Kr(AccountType.PKr PKr) {
			this.PKr = PKr;
		}
	}

	public static class GIn {
		public AccountType.SK SKr;
		public Out Out;
		public Witness Witness;
		public Field.FR A;
		public Field.FR Ar;

		public GIn() {
		}

		public GIn(Types.Out out, Types.Witness witness) {
			Out = out;
			Witness = witness;
		}
	}

	public static class GOut {
		public AccountType.PKr PKr;
		public Asset Asset;
		public byte[] Memo;
		public Field.FR Ar;

		public GOut() {
		}

		public GOut(AccountType.PKr PKr, Types.Asset asset, byte[] memo) {
			this.PKr = PKr;
			Asset = asset;
			Memo = memo;
		}
	}

	public static class GTxParam {
		public BigInteger Gas;
		public BigInteger GasPrice;
		public Token Fee;
		public Kr From;
		public List<GIn> Ins;
		public List<GOut> Outs;
		public Cmds Cmds;
		public boolean Z;

		public GTxParam() {
		}

		public GTxParam(Token fee, BigInteger gasPrice, Kr from) {
			GasPrice = gasPrice;
			Gas = fee.Value.divide(gasPrice);
			Fee = fee;
			From = from;
		}
	}

	public static class ContractCmd {
		public Asset Asset;
		public AccountType.PKr To;
		public byte[] Data;

		public byte[] hash() {
			List<byte[]> list = Lists.newArrayList(Asset.hash());
			if (To != null) {
				list.add(To.toBytes());
			}
			list.add(Data);
			return HashUtil.sha3(Arrays.concat(list));
		}
	}

	public static class Reception {
		public AccountType.PKr Addr;
		public Asset Asset;
	}

	public static class PreTxParam {
		public AccountType.PKr From;
		public AccountType.PKr RefundTo;
		public List<Reception> Receptions;
		public Cmds Cmds;
		public Token Fee;
		public BigInteger GasPrice;
	}

	public static class Cmds {
		public ContractCmd Contract;

		public Cmds() {
		}

		public Cmds(ContractCmd contract) {
			Contract = contract;
		}
	}

	public static class PkgDesc_Z {
		
		public PkgDesc_Z() {
		}

		public byte[] hash() {
			return HashUtil.sha3(new byte[0]);
		}
	}

	public static class DescCmd {
		public ContractCmd Contract;

		public byte[] hash() {
			List<byte[]> list = Lists.newArrayList();
			if (Contract != null) {
				list.add(Contract.hash());
			}
			return HashUtil.sha3(list);
		}
	}

	public static class Token {
		public byte[] Currency;
		public BigInteger Value;

		public Token() {
		}

		public Token(byte[] currency, BigInteger value) {
			Currency = currency;
			Value = value;
		}

		public byte[] toBytes() {
			return Arrays.concat(Currency, Arrays.rightPadBytes(Arrays.reverse(Value.toByteArray()), 32));
		}

		public byte[] hash() {
			return HashUtil.sha3(this.toBytes());
		}
	}

	public static class Ticket {
		public byte[] Category;
		public byte[] Value;

		public Ticket() {
		}

		public Ticket(byte[] category, byte[] value) {
			Category = category;
			Value = value;
		}

		public byte[] toBytes() {
			return Arrays.concat(Category, this.Value);
		}

		public byte[] hash() {
			return HashUtil.sha3(this.toBytes());
		}
	}

	public static class Asset {
		public Token Tkn;
		public Ticket Tkt;

		public byte[] hash() {
			List<byte[]> list = Lists.newArrayList();
			if (this.Tkn != null) {
				list.add(this.Tkn.hash());
			}
			if (this.Tkt != null) {
				list.add(Tkt.hash());
			}
			return HashUtil.sha3(list);
		}

		public org.sero.cash.superzk.protocol.Asset toAsset() {
			byte[] tkn_current;
			Field.FR tkn_value;
			byte[] tkt_category;
			byte[] tkt_value;
			if (this.Tkn != null) {
				tkn_current = this.Tkn.Currency;
				tkn_value = Field.newFR(this.Tkn.Value);
			} else {
				tkn_current = new byte[32];
				tkn_value = Field.FR.ZERO;
			}
			if (this.Tkt != null) {
				tkt_category = this.Tkt.Category;
				tkt_value = Hex.decode(this.Tkt.Value);
			} else {
				tkt_category = new byte[32];
				tkt_value = new byte[32];
			}
			return new org.sero.cash.superzk.protocol.Asset(tkn_current, tkn_value, tkt_category, tkt_value);
		}
	}

	public static class Witness {
		public String Pos;
		public List<String> Paths; // 29
		public byte[] Anchor;
	}

	public static class Out_O {
		public AccountType.PKr Addr;
		public Asset Asset;
		public byte[] Memo;

		public byte[] toHash() {
			return HashUtil.sha3(this.Addr.toBytes(), this.Asset.hash(), this.Memo);
		}
	}

	public static class Out_Z {
		public byte[] AssetCM;
		public byte[] OutCM;
		public byte[] RPK;
		public byte[] EInfo;
		public AccountType.PKr PKr;
		public byte[] Proof;

		public byte[] toHash() {
			return HashUtil.sha3(this.AssetCM, this.OutCM, this.EInfo, this.PKr.toBytes(), HashUtil.sha3(this.Proof));
		}
	}

	public static class ZPkg {
		public int High;
		public String From;
		public PkgCreate Pack;
		public Boolean Closed;
	}

	public static class Pkg_Z {
		public String AssetCM;
		public String PkgCM;
		public String EInfo;
	}

	public static class PkgCreate {
		public String Id;
		public String PKr;
		public Pkg_Z Pkg;
		public String Proof;
	}

	public static class OutState {
		public int Index;
		public Out_O Out_O;
		public Out_Z Out_Z;
		public Out_P Out_P;
		public Out_C Out_C;
		public String OutCM;
		public Point RootCM;

		public AccountType.PKr getPkr() {
			if (Out_O != null) {
				return Out_O.Addr;
			} else if (Out_Z != null) {
				return Out_Z.PKr;
			} else if (Out_P != null) {
				return Out_P.PKr;
			} else if (Out_C != null) {
				return Out_C.PKr;
			}
			return null;
		}
	}

	public static class Out {
		public byte[] Root;
		public RootState State;

		public Out() {
		}

		public Out(byte[] root, RootState state) {
			Root = root;
			State = state;
		}
	}

	public static class TDOut {
		public Asset Asset;
		public byte[] Memo;
		public List<byte[]> Nils;

		public TDOut() {
		}

		public TDOut(Types.Asset asset, byte[] memo, List<byte[]> nils) {
			Asset = asset;
			Memo = memo;
			Nils = nils;
		}
	}

	public static class RootState {
		public OutState OS;
		public byte[] TxHash;
		public long Num;
	}

	public static class In_S {
		public byte[] Root;
		public byte[] Nil;
		public byte[] Sign;

		public byte[] toHash() {
			return HashUtil.sha3(this.Root, this.Nil, this.Sign);
		}
	}

	public static class In_Z {
		public byte[] Anchor;
		public byte[] Nil;
		public byte[] Trace;
		public byte[] AssetCM;
		public byte[] Proof;

		public byte[] toHash() {
			return HashUtil.sha3(this.Anchor, this.Nil, this.Trace, this.AssetCM, HashUtil.sha3(this.Proof));
		}
	}

	public static class Desc_O {
		public List<In_S> Ins;
		public List<Out_O> Outs;

		public byte[] toHash() {
			List<byte[]> list = Lists.newArrayList();
			if (CollectionUtils.isNotEmpty(this.Ins)) {
				this.Ins.forEach(each -> {
					list.add(each.toHash());
				});
			}
			if (CollectionUtils.isNotEmpty(this.Outs)) {
				this.Outs.forEach(each -> {
					list.add(each.toHash());
				});
			}
			return HashUtil.sha3(list);
		}
	}

	public static class Desc_Z {
		public List<In_Z> Ins;
		public List<Out_Z> Outs;

		public byte[] toHash() {
			List<byte[]> list = Lists.newArrayList();
			if (CollectionUtils.isNotEmpty(this.Ins)) {
				this.Ins.forEach(each -> {
					list.add(each.toHash());
				});
			}
			if (CollectionUtils.isNotEmpty(this.Outs)) {
				this.Outs.forEach(each -> {
					list.add(each.toHash());
				});
			}
			return HashUtil.sha3(list);
		}
	}

	public static class In_P {
		public byte[] Root;
		public byte[] Nil;
		public byte[] Key;
		public byte[] NSign;
		public byte[] ASign;

		public In_P() {
		}

		public In_P(byte[] root) {
			Root = root;
		}

		public byte[] hash() {
			List<byte[]> list = Lists.newArrayList();
			list.add(Root);
			list.add(Nil);
			if (Key != null) {
				list.add(Key);
			}
			list.add(new byte[0]);
			return HashUtil.sha3(list);
		}

		public byte[] toHash() {
			List<byte[]> list = Lists.newArrayList();
			list.add(Root);
			list.add(Nil);
			if (Key != null) {
				list.add(Key);
			}
			list.add(NSign);
			list.add(ASign);
			return HashUtil.sha3(list);
		}
	}

	public static class In_P0 {
		public byte[] Root;
		public Point Nil;
		public Point Trace;
		public byte[] Key;
		public byte[] Sign;

		public In_P0() {
		}

		public In_P0(byte[] root) {
			Root = root;
		}

		public byte[] hash() {
			List<byte[]> list = Lists.newArrayList();
			list.add(Root);
			list.add(Nil.toBytes());
			list.add(Trace.toBytes());
			if (Key != null) {
				list.add(Key);
			}
			return HashUtil.sha3(list);
		}

		public byte[] toHash() {
			List<byte[]> list = Lists.newArrayList(this.Root, this.Nil.toBytes(), this.Trace.toBytes());
			if (this.Key != null) {
				list.add(this.Key);
			}
			list.add(this.Sign);
			return HashUtil.sha3(list);
		}
	}

	public static class In_C {
		public byte[] Anchor;
		public byte[] Nil;
		public Point AssetCM;
		public Point ZPKa;
		public byte[] Sign;
		public byte[] Proof;

		public In_C() {
			Proof = new byte[131];
		}

		public byte[] hash() {
			return HashUtil.sha3(Anchor, Nil, AssetCM.toBytes(), ZPKa.toBytes());
		}

		public byte[] toHash() {
			return HashUtil.sha3(Anchor, Nil, AssetCM.toBytes(), ZPKa.toBytes(), Sign, Proof);
		}
	}

	public static class Out_P {
		public AccountType.PKr PKr;
		public Asset Asset;
		public byte[] Memo;

		public Out_P() {
		}

		public Out_P(AccountType.PKr PKr, Types.Asset asset, byte[] memo) {
			this.PKr = PKr;
			Asset = asset;
			Memo = memo;
		}

		public byte[] hash() {
			return HashUtil.sha3(PKr.toBytes(), Asset.hash(), Memo);
		}

		public byte[] toHash() {
			return HashUtil.sha3(PKr.toBytes(), Asset.hash(), Memo);
		}
	}

	public static class Out_C {
		public AccountType.PKr PKr;
		public Point AssetCM;
		public byte[] RPK;
		public byte[] EInfo;
		public byte[] Proof;

		public Out_C() {
			Proof = new byte[131];
		}

		public byte[] hash() {
			return HashUtil.sha3(PKr.toBytes(), AssetCM.toBytes(), RPK, EInfo);
		}

		public byte[] toHash() {
			return HashUtil.sha3(PKr.toBytes(), AssetCM.toBytes(), RPK, EInfo, Proof);
		}
	}

	public static class Tx {
		public List<In_P> Ins_P;
		public List<In_P0> Ins_P0;
		public List<In_C> Ins_C;
		public List<Out_C> Outs_C;
		public List<Out_P> Outs_P;

		public Tx() {
			Ins_P = new ArrayList<In_P>();
			Ins_P0 = new ArrayList<In_P0>();
			Ins_C = new ArrayList<In_C>();
			Outs_C = new ArrayList<Out_C>();
			Outs_P = new ArrayList<Out_P>();
		}

		public byte[] hash() {
			List<byte[]> list = Lists.newArrayList();
			if (this.Ins_P0.size() > 0) {
				this.Ins_P0.forEach(each -> {
					list.add(each.hash());
				});
			}

			if (this.Ins_P.size() > 0) {
				this.Ins_P.forEach(each -> {
					list.add(each.hash());
				});
			}
			if (this.Ins_C.size() > 0) {
				this.Ins_C.forEach(each -> {
					list.add(each.hash());
				});
			}
			if (this.Outs_C.size() > 0) {
				this.Outs_C.forEach(each -> {
					list.add(each.hash());
				});
			}
			if (this.Outs_P.size() > 0) {
				this.Outs_P.forEach(each -> {
					list.add(each.hash());
				});
			}
			return HashUtil.sha3(list);
		}

		public byte[] toHash() {

			List<byte[]> list = Lists.newArrayList();
			if (this.Ins_P0.size() > 0) {
				this.Ins_P0.forEach(each -> {
					list.add(each.toHash());
				});
			}

			if (this.Ins_P.size() > 0) {
				this.Ins_P.forEach(each -> {
					list.add(each.toHash());
				});
			}
			if (this.Ins_C.size() > 0) {
				this.Ins_C.forEach(each -> {
					list.add(each.toHash());
				});
			}
			if (this.Outs_C.size() > 0) {
				this.Outs_C.forEach(each -> {
					list.add(each.toHash());
				});
			}
			if (this.Outs_P.size() > 0) {
				this.Outs_P.forEach(each -> {
					list.add(each.toHash());
				});
			}
			return HashUtil.sha3(list);
		}
	}

	public static class T {
		public byte[] Ehash;
		public AccountType.PKr From;
		public Token Fee;
		public byte[] Sign;
		public byte[] Bcr;
		public byte[] Bsign;
		public Desc_O Desc_O;
		public Desc_Z Desc_Z;
		public PkgDesc_Z Desc_Pkg;
		public DescCmd Desc_Cmd;
		public Tx Tx1;

		public T() {
			Desc_O = new Desc_O();
			Desc_Z = new Desc_Z();
			Desc_Pkg = new PkgDesc_Z();
			Desc_Cmd = new DescCmd();
			Tx1 = new Tx();
			Bcr = new byte[32];
			Bsign = new byte[64];
		}

		public byte[] hash() {			
			return HashUtil.sha3(baseHash(), Desc_Cmd.hash(), Desc_Pkg.hash(), Tx1.hash());
		}

		public byte[] baseHash() {
			return HashUtil.sha3(Ehash, From.toBytes(), Fee.hash());
		}

		public byte[] toHash() {
			List<byte[]> list = Lists.newArrayList(this.Ehash, this.From.toBytes(), this.Fee.hash());

			list.add(this.Desc_Z.toHash());
			list.add(this.Desc_O.toHash());

			if (CollectionUtils.isNotEmpty(this.Tx1.Ins_P) || CollectionUtils.isNotEmpty(this.Tx1.Ins_P0)
					|| CollectionUtils.isNotEmpty(this.Tx1.Ins_C) || CollectionUtils.isNotEmpty(this.Tx1.Outs_C)
					|| CollectionUtils.isNotEmpty(this.Tx1.Outs_P)) {

				list.add(this.Tx1.toHash());
			}

			list.add(this.Desc_Pkg.hash());
			list.add(this.Sign);
			list.add(this.Bcr);
			list.add(this.Bsign);
			if (this.Desc_Cmd.Contract != null) {
				list.add(this.Desc_Cmd.hash());
			}
			return HashUtil.sha3(list);
		}
	}

	public static class GTx {
		public String Gas;
		public String GasPrice;
		public T Tx;
		public byte[] Hash;

		public GTx(String gas, String gasPrice, T tx, byte[] hash) {
			Gas = gas;
			GasPrice = gasPrice;
			Tx = tx;
			Hash = hash;
		}
	}

}
