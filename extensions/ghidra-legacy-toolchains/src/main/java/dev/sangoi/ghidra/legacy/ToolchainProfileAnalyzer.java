package dev.sangoi.ghidra.legacy;

import java.lang.reflect.InvocationTargetException;

import dev.sangoi.ghidra.legacy.profiles.Bcc20Profile;
import dev.sangoi.ghidra.legacy.profiles.Bcc31Profile;
import dev.sangoi.ghidra.legacy.profiles.Bcc45Profile;
import dev.sangoi.ghidra.legacy.profiles.ScranticRuntimeProfile;
import dev.sangoi.ghidra.legacy.profiles.SimTowerRuntimeProfile;
import dev.sangoi.ghidra.legacy.profiles.Tasm31Profile;
import dev.sangoi.ghidra.legacy.profiles.Tlink401Profile;
import dev.sangoi.ghidra.legacy.profiles.Tlink51Profile;
import ghidra.app.plugin.core.analysis.AnalysisWorker;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/** Applies exact tool-image facts and supplied-application runtime correspondence, without historical compiler attribution. */
public class ToolchainProfileAnalyzer extends AbstractAnalyzer {
    public static final String NAME = "Legacy toolchain exact-image profiles";
    private final ToolchainProfile[] profiles = {
        new Bcc20Profile(), new Bcc31Profile(), new Bcc45Profile(), new Tasm31Profile(),
        new Tlink401Profile(), new Tlink51Profile(), new ScranticRuntimeProfile(), new SimTowerRuntimeProfile()
    };

    public ToolchainProfileAnalyzer() {
        super(NAME, "Apply exact tool-image layouts and supplied-application runtime correspondence using native original-file provenance, without historical compiler attribution.", AnalyzerType.BYTE_ANALYZER);
        setPriority(AnalysisPriority.LOW_PRIORITY.after().after());
        setDefaultEnablement(true);
        setSupportsOneTimeAnalysis();
    }

    @Override
    public boolean canAnalyze(Program program) {
        String language = program.getLanguageID().toString();
        if (!language.equals("x86:LE:16:Protected Mode") && !language.equals("x86:LE:16:Real Mode")) {
            return false;
        }
        try {
            for (ToolchainProfile profile : profiles) {
                if (profile.match(program, TaskMonitor.DUMMY) != null) {
                    return true;
                }
            }
        }
        catch (Exception e) {
            Msg.error(this, "Unable to qualify original image provenance", e);
        }
        return false;
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) throws CancelledException {
        if (!canAnalyze(program)) {
            return true;
        }
        for (ToolchainProfile profile : profiles) {
            try {
                ToolchainProfile.Context context = profile.match(program, monitor);
                if (context != null) {
                    // Imported facts must not enqueue heuristic rediscovery or purge inference.
                    // The native worker owns suspension/restoration in analyzer and script contexts.
                    boolean applied = AutoAnalysisManager.getAnalysisManager(program).scheduleWorker(new AnalysisWorker() {
                        @Override
                        public String getWorkerName() {
                            return NAME + ": " + profile.id();
                        }

                        @Override
                        public boolean analysisWorkerCallback(Program target, Object workerContext, TaskMonitor workerMonitor) throws Exception {
                            profile.apply((ToolchainProfile.Context) workerContext, workerMonitor, log);
                            return true;
                        }
                    }, context, false, monitor);
                    if (!applied) {
                        return false;
                    }
                    log.appendMsg(NAME, "Applied " + profile.id() + " to qualified original FileBytes in native analysis-worker batch");
                }
            }
            catch (CancelledException e) {
                throw e;
            }
            catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new CancelledException();
            }
            catch (Exception e) {
                Throwable failure = e instanceof InvocationTargetException invocation ? invocation.getCause() : e;
                if (failure instanceof CancelledException cancellation) {
                    throw cancellation;
                }
                log.appendMsg(NAME, "Profile " + profile.id() + " failed visibly: " + failure.getMessage());
                log.appendException(failure);
                return false;
            }
        }
        return true;
    }
}
