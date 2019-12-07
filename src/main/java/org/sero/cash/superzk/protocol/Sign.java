package org.sero.cash.superzk.protocol;

import java.util.ArrayList;
import java.util.List;

import org.ethereum.crypto.HashUtil;
import org.ethereum.util.RLP;
import org.sero.cash.superzk.crypto.ecc.Field;
import org.sero.cash.superzk.crypto.ecc.Point;
import org.sero.cash.superzk.protocol.czero.Czero;
import org.sero.cash.superzk.protocol.superzk.Account;
import org.sero.cash.superzk.protocol.superzk.SuperZk;

public class Sign {

	private static class BalanceDesc {
		public byte[] hash;
		public Types.Params param;

		BalanceDesc() {
			param = new Types.Params();
		}
	}

	private static class Context {
		private Types.GTxParam param;

		public List<Types.GIn> p0_ins = new ArrayList<Types.GIn>();
		public List<Types.GIn> p_ins = new ArrayList<Types.GIn>();;
		public List<Types.GIn> c_ins = new ArrayList<Types.GIn>();;
		public List<Types.GOut> c_outs = new ArrayList<Types.GOut>();
		public List<Types.GOut> p_outs = new ArrayList<Types.GOut>();
		public List<byte[]> keys = new ArrayList<byte[]>();
		public BalanceDesc balance_desc = new BalanceDesc();
		public Types.T s = new Types.T();

		public Context(Types.GTxParam param) {
			this.param = param;
		}
	}

	public static Types.GTx signTx(Types.GTxParam param) {
		check(param);
		Context ctx = new Context(param);
		prepare(ctx);
		genFrom(ctx);
		genFee(ctx);
		genCmd(ctx);
		genInsP0(ctx);
		genInsP(ctx);
		genInsC(ctx);
		genOutsC(ctx);
		genOutsP(ctx);
		genSign(ctx);

		return new Types.GTx(param.Gas, param.GasPrice, ctx.s, ctx.s.toHash());
	}

	private static void check(Types.GTxParam param) {

		if (param.From.SKr == null) {
			throw new RuntimeException("sk is undifined!");
		}
		AccountType.TK tk = param.From.SKr.toTK();
		if (!tk.isMyPKr(param.From.PKr)) {
			throw new Error("sk unmatch pkr for the From field");
		}

		param.Ins.forEach(item -> {
			if (item.Out.State.OS.Out_O != null) {
				if (!tk.isMyPKr(item.Out.State.OS.Out_O.Addr)) {
					throw new Error("sk unmatch pkr for the From field");
				}
			} else if (item.Out.State.OS.Out_Z != null) {
				if (!tk.isMyPKr(item.Out.State.OS.Out_Z.PKr)) {
					throw new Error("sk unmatch pkr for the From field");
				}
			} else if (item.Out.State.OS.Out_P != null) {
				if (!tk.isMyPKr(item.Out.State.OS.Out_P.PKr)) {
					throw new Error("sk unmatch pkr for the From field");
				}
			} else if (item.Out.State.OS.Out_C != null) {
				if (!tk.isMyPKr(item.Out.State.OS.Out_C.PKr)) {
					throw new Error("sk unmatch pkr for the From field");
				}
			}
		});
	}

	private static void prepare(Context ctx) {
		ctx.param.Ins.forEach(item -> {
			if (item.Out.State.OS.Out_O != null) {
				ctx.p0_ins.add(item);
			} else if (item.Out.State.OS.Out_Z != null) {
				ctx.p0_ins.add(item);
			} else if (item.Out.State.OS.Out_P != null) {
				ctx.p_ins.add(item);
			} else if (item.Out.State.OS.Out_C != null) {
				if (ctx.param.Z) {
					ctx.c_ins.add(item);
				} else {
					ctx.p_ins.add(item);
				}
			}
		});

		ctx.param.Outs.forEach(item -> {
			if (Param.isFlagSet(item.PKr.toBytes()) && ctx.param.Z) {
				ctx.c_outs.add(item);
			} else {
				ctx.p_outs.add(item);
			}
		});

		ctx.s.Ehash = HashUtil
				.sha3(RLP.encode(new Object[] {ctx.param.GasPrice.toByteArray(), ctx.param.Gas.toByteArray(), new byte[0]}));
	}

	private static void genFrom(Context ctx) {
		ctx.s.From = ctx.param.From.PKr;
	}

	private static Asset tokenToAsset(Types.Token tkn) {
		return new Asset(tkn.Currency, Field.newFR(tkn.Value), new byte[32], new byte[32]);
	}

	private static void genFee(Context ctx) {
		ctx.s.Fee = ctx.param.Fee;
		Asset asset = tokenToAsset(ctx.s.Fee);
		ctx.balance_desc.param.oout_accs.add(asset.genAssetCC());
	}

	private static void genCmd(Context ctx) {
		Types.Asset a = null;
		if (ctx.param.Cmds != null && ctx.param.Cmds.Contract != null) {
			ctx.s.Desc_Cmd.Contract = ctx.param.Cmds.Contract;
			a = ctx.param.Cmds.Contract.Asset;
		}
		if (null != a) {
			Point cc = a.toAsset().genAssetCC();
			ctx.balance_desc.param.oout_accs.add(cc);
		}
	}

	private static void genInsP0(Context self) {
		if (self.s.Tx1.Ins_P0 == null) {
			self.s.Tx1.Ins_P0 = new ArrayList<Types.In_P0>();
		}
		self.p0_ins.forEach(item -> {
			AccountType.SK sk = item.SKr;
			AccountType.TK tk = sk.toTK();
			Types.In_P0 t_in = new Types.In_P0(item.Out.Root);

			t_in.Trace = Czero.genTrace(tk, item.Out.State.OS.RootCM);
			t_in.Nil = Czero.genNil(sk, item.Out.State.OS.RootCM);

			if (item.Out.State.OS.Out_O != null) {
				self.balance_desc.param.oin_accs.add(item.Out.State.OS.Out_O.Asset.toAsset().genAssetCC());
			} else {
				Types.Out_Z outz = item.Out.State.OS.Out_Z;
				t_in.Key = Czero.fetchKey(tk, outz.RPK);

				Types.TDOut out = Czero.confirmOutZ(t_in.Key, outz.EInfo, outz.PKr, outz.OutCM);
				
				if (out != null) {
					self.balance_desc.param.oin_accs.add(out.Asset.toAsset().genAssetCC());
				} else {
					throw new RuntimeException("gen tx1 confirm outz error");
				}
			}
			self.s.Tx1.Ins_P0.add(t_in);
		});
	}

	public static void genInsP(Context self) {
		self.p_ins.forEach(item -> {
			AccountType.TK tk = item.SKr.toTK();
			Types.In_P t_in = new Types.In_P(item.Out.Root);

			if (item.Out.State.OS.Out_P != null) {
				Types.Out_P out_p = item.Out.State.OS.Out_P;
				t_in.Nil = SuperZk.genNil(tk, item.Out.State.OS.RootCM, out_p.PKr);
				self.balance_desc.param.oin_accs.add(out_p.Asset.toAsset().genAssetCC());
			} else {
				Types.Out_C out_c = item.Out.State.OS.Out_C;
				t_in.Nil = SuperZk.genNil(tk, item.Out.State.OS.RootCM, out_c.PKr);
				t_in.Key = SuperZk.fetchRPKKey(out_c.PKr, tk, out_c.RPK);
				Types.TDOut out = SuperZk.confirmOutC(t_in.Key, out_c.EInfo, out_c.AssetCM);
				if (out != null) {
					self.balance_desc.param.oin_accs.add(out.Asset.toAsset().genAssetCC());
				} else {
					throw new RuntimeException("gen tx1 confirm outz error");
				}
			}
			self.s.Tx1.Ins_P.add(t_in);
		});
	}

	public static void genInsC(Context self) {
		self.c_ins.forEach(item -> {
			AccountType.TK tk = item.SKr.toTK();
			Types.In_C t_in = new Types.In_C();

			Types.Out_C out = item.Out.State.OS.Out_C;
			t_in.Nil = SuperZk.genNil(tk, item.Out.State.OS.RootCM, out.PKr);

			byte[] key = SuperZk.fetchRPKKey(out.PKr, tk, out.RPK);
			self.keys.add(key);

			SuperZk.Info info = SuperZk.decEInfo(key, out.EInfo);
			item.Ar = Field.randomFR();
			t_in.AssetCM = info.asset.genAssetCM(item.Ar);
			item.A = Field.randomFR();
			t_in.ZPKa = SuperZk.genZPKa((Account.PKr) out.PKr, item.A);
			t_in.Anchor = item.Witness.Anchor;

			self.balance_desc.param.zin_acms.add(t_in.AssetCM);
			self.balance_desc.param.zin_ars.add(item.Ar);
			self.s.Tx1.Ins_C.add(t_in);
		});
	}

	public static void genOutsC(Context self) {
		self.c_outs.forEach(out -> {
			Types.Out_C t_out = new Types.Out_C();
			out.Ar = Field.randomFR();
			Asset asset = out.Asset.toAsset();
			t_out.AssetCM = asset.genAssetCM(out.Ar);
			t_out.PKr = out.PKr;
			byte[][] bytes = SuperZk.genPKrKey(out.PKr, Field.randomFR());
			t_out.RPK = bytes[1];

			SuperZk.Info info = new SuperZk.Info(asset, out.Memo, out.Ar);
			t_out.EInfo = SuperZk.encInfo(bytes[0], info);

			self.balance_desc.param.zout_acms.add(t_out.AssetCM);
			self.balance_desc.param.zout_ars.add(out.Ar);
			self.s.Tx1.Outs_C.add(t_out);
		});
	}

	public static void genOutsP(Context self) {
		self.p_outs.forEach(out -> {
			Types.Out_P t_out = new Types.Out_P(out.PKr, out.Asset, out.Memo);
			Point assetCC = out.Asset.toAsset().genAssetCC();
			self.balance_desc.param.oout_accs.add(assetCC);
			self.s.Tx1.Outs_P.add(t_out);
		});
	}

	public static class Tx1Hash {

	}

	public static void genSign(Context self) {
		self.balance_desc.hash = self.s.hash();
		if (self.param.From.SKr != null) {
			if (Param.isFlagSet(self.s.From.toBytes())) {
				self.s.Sign = SuperZk.signPKr(self.param.From.SKr, self.balance_desc.hash, self.s.From);
			} else {
				self.s.Sign = Czero.signByPKr(self.param.From.SKr, self.balance_desc.hash, self.s.From);
			}
		} else {
			throw new RuntimeException("skr is undefined");
		}

		if (self.s.Tx1.Ins_P0.size() > 0) {
			for (int i = 0; i < self.s.Tx1.Ins_P0.size(); i++) {
				Types.GIn in = self.p0_ins.get(i);
				AccountType.PKr pkr = in.Out.State.OS.getPkr();
				self.s.Tx1.Ins_P0.get(i).Sign = Czero.signNil(self.balance_desc.hash, in.SKr, pkr,
						in.Out.State.OS.RootCM);
			}
		}

		if (self.s.Tx1.Ins_P.size() > 0) {
			for (int i = 0; i < self.s.Tx1.Ins_P.size(); i++) {
				Types.GIn in = self.p_ins.get(i);
				AccountType.PKr pkr = in.Out.State.OS.getPkr();
				self.s.Tx1.Ins_P.get(i).ASign = SuperZk.signPKr(in.SKr, self.balance_desc.hash, pkr);
				self.s.Tx1.Ins_P.get(i).NSign = SuperZk.signNil(self.balance_desc.hash, in.SKr.toTK(),
						in.Out.State.OS.RootCM, pkr);
			}
		}

		if (self.s.Tx1.Ins_C.size() > 0) {
			for (int i = 0; i < self.s.Tx1.Ins_C.size(); i++) {
				Types.GIn in = self.c_ins.get(i);
				AccountType.PKr pkr = in.Out.State.OS.getPkr();
				self.s.Tx1.Ins_C.get(i).Sign = SuperZk.signZPKa(self.balance_desc.hash, in.SKr, in.A, pkr);
			}
		}

		if (self.balance_desc.param.zin_acms.size() > 0 || self.balance_desc.param.zout_acms.size() > 0) {
			byte[][] ret = Param.signBalance(self.balance_desc.hash, self.balance_desc.param);
			if (ret != null) {
				self.s.Bcr = ret[0];
				self.s.Bsign = ret[1];
			}
		}

		return;
	}
}
