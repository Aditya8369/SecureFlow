import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/auth";
import prisma from "@/lib/prisma";

export async function POST(req: NextRequest) {
  try {
    const session = await auth();
    if (!session?.user?.id) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const body = await req.json();
    const { action, findingIds } = body; // action: 'apply' | 'rollback'

    if (!Array.isArray(findingIds) || findingIds.length === 0) {
      return NextResponse.json({ error: "No finding IDs provided" }, { status: 400 });
    }

    const newStatus = action === "rollback" ? "PENDING" : "APPLIED";

    // Update patches in bulk
    await prisma.remediationPatch.updateMany({
      where: { findingId: { in: findingIds } },
      data: { status: newStatus },
    });

    return NextResponse.json({ success: true, updatedCount: findingIds.length, status: newStatus });
  } catch (error) {
    console.error("[BULK_REMEDIATE_ERROR]", error);
    return NextResponse.json({ error: "Internal Server Error" }, { status: 500 });
  }
}
