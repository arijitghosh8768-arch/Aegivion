"use client";

import { useState } from "react";
import { Plus, CheckCircle2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

export function CreateRunbookDialog() {
  const [open, setOpen] = useState(false);
  const [step, setStep] = useState(1);

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="outline">
          <Plus className="h-4 w-4 mr-1.5" /> Create Runbook
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-[500px]">
        <DialogHeader>
          <DialogTitle>Create New Runbook</DialogTitle>
          <DialogDescription>
            Configure automated response rules for security findings. Step {step} of 6.
          </DialogDescription>
        </DialogHeader>
        
        {step === 1 && (
          <div className="grid gap-4 py-4">
            <div className="grid gap-2">
              <Label htmlFor="name">Runbook Name</Label>
              <Input id="name" placeholder="e.g. Isolate Compromised EC2" />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="desc">Description</Label>
              <Input id="desc" placeholder="What does this runbook do?" />
            </div>
          </div>
        )}

        {step > 1 && step < 6 && (
          <div className="py-8 text-center text-muted-foreground">
            Configuration for Step {step} goes here.
          </div>
        )}

        {step === 6 && (
          <div className="py-8 text-center text-success flex flex-col items-center">
            <CheckCircle2 className="h-12 w-12 mb-4" />
            <h3 className="text-lg font-semibold">Review & Activate</h3>
            <p className="text-sm text-muted-foreground">The runbook is ready to be enabled.</p>
          </div>
        )}

        <DialogFooter>
          {step > 1 && (
            <Button variant="outline" onClick={() => setStep(step - 1)}>
              Back
            </Button>
          )}
          {step < 6 ? (
            <Button onClick={() => setStep(step + 1)}>
              Next Step
            </Button>
          ) : (
            <Button variant="gradient" onClick={() => { setOpen(false); setStep(1); }}>
              Activate Runbook
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
