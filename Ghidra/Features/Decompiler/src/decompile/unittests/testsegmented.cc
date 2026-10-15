/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "architecture.hh"
#include "funcdata.hh"
#include "grammar.hh"
#include "printc.hh"
#include "printjava.hh"
#include "ruleaction.hh"
#include "test.hh"

namespace ghidra {

// These local owner tests exercise native-generated stack references and printer sugar, which cannot be specified by instruction bytes alone.
class SegmentedEnvironment {
public:
  Architecture *arch;
  Funcdata *fd;
  BlockBasic *block;
  SegmentedEnvironment(void) {
    istringstream s("<binaryimage arch=\"x86:LE:16:Protected Mode:default\"></binaryimage>");
    DocumentStorage store;
    Document *doc = store.parseDocument(s);
    store.registerTag(doc->getRoot());
    arch = ArchitectureCapability::getCapability("xml")->buildArchitecture("", "", &cout);
    arch->init(store);
    fd = arch->symboltab->getGlobalScope()->addFunction(Address(arch->getDefaultCodeSpace(),0x1000),"segmented_test")->getFunction();
    fd->setHighLevel();
    block = new BlockBasic(fd);
  }
  ~SegmentedEnvironment(void) {
    delete arch;
    delete block;
  }
  PcodeOp *op(OpCode code,const vector<Varnode *> &inputs,Datatype *outType = (Datatype *)0) {
    PcodeOp *res = fd->newOp(inputs.size(),fd->getAddress());
    fd->opSetOpcode(res,code);
    for(int4 i=0;i<inputs.size();++i)
      fd->opSetInput(res,inputs[i],i);
    if (outType != (Datatype *)0) {
      Varnode *out = fd->newUniqueOut(outType->getSize(),res);
      out->updateType(outType,true,true);
      out->setImplied();
    }
    fd->opInsertEnd(res,block);
    return res;
  }
  Varnode *constant(int4 size,uintb value,Datatype *type = (Datatype *)0) {
    Varnode *vn = fd->newConstant(size,value);
    if (type != (Datatype *)0)
      vn->updateType(type,true,true);
    return vn;
  }
  Varnode *segment(Varnode *selector,Varnode *offset,Datatype *type) {
    return op(CPUI_SEGMENTOP,{fd->newVarnodeSpace(arch->getDefaultDataSpace()),selector,offset},type)->getOut();
  }
};

template<typename Printer> class SegmentedExpressionPrinter : public Printer {
public:
  SegmentedExpressionPrinter(Architecture *arch) : Printer(arch) {
    this->initializeFromArchitecture();
  }
  string expression(const PcodeOp *op) {
    ostringstream output;
    this->clear();
    this->setOutputStream(&output);
    op->getOpcode()->push(this,op,(const PcodeOp *)0);
    this->recurse();
    this->emit->flush();
    this->setOutputStream((ostream *)0);
    return output.str();
  }
};

TEST(segmented_spacebase) {
  SegmentedEnvironment env;
  AddrSpace *stack = env.arch->getStackSpace();
  Varnode *sp = env.fd->constructSpacebaseInput(stack);
  Datatype *word = env.arch->types->getBase(2,TYPE_UNKNOWN);
  PcodeOp *anchor = env.op(CPUI_COPY,{env.constant(2,0)},word);
  Varnode *offset = env.fd->createStackRef(stack,0x10,anchor,sp,false);
  ASSERT_EQUALS(offset->getSize(),sp->getSize());
  ASSERT_EQUALS(offset->getDef()->code(),CPUI_INT_ADD);
  PcodeOp *load = env.op(CPUI_LOAD,{env.fd->newVarnodeSpace(stack->getContain()),offset},word);
  RuleLoadVarnode loadRule("base");
  ASSERT_EQUALS(loadRule.applyOp(load,*env.fd),1);
  ASSERT_EQUALS(load->code(),CPUI_COPY);
  ASSERT_EQUALS(load->getIn(0)->getSpace(),stack);
  ASSERT_EQUALS(load->getIn(0)->getOffset(),0x10);
  Varnode *stackValue = env.fd->opStackLoad(stack,0x14,4,anchor,sp,false);
  PcodeOp *stackLoad = stackValue->getDef();
  ASSERT_EQUALS(stackValue->getSize(),4);
  ASSERT_EQUALS(stackLoad->getIn(1)->getSize(),2);
  ASSERT_EQUALS(loadRule.applyOp(stackLoad,*env.fd),1);
  ASSERT_EQUALS(stackLoad->getIn(0)->getSpace(),stack);
  ASSERT_EQUALS(stackLoad->getIn(0)->getOffset(),0x14);
  PcodeOp *store = env.fd->opStackStore(stack,0x12,anchor,false);
  env.fd->opSetInput(store,env.constant(2,0xaabb),2);
  PcodeOp *storeOffset = store->getIn(1)->getDef();
  // Bind the newly generated free SP reference as heritage does before normalization.
  env.fd->opSetInput(storeOffset,env.fd->setInputVarnode(storeOffset->getIn(0)),0);
  RuleStoreVarnode storeRule("base");
  ASSERT_EQUALS(storeRule.applyOp(store,*env.fd),1);
  ASSERT_EQUALS(store->getOut()->getSpace(),stack);
  ASSERT_EQUALS(store->getOut()->getOffset(),0x12);
  // A genuine literal-zero selector is not a synthetic stack reference.
  Varnode *address = env.segment(env.constant(2,0),offset,env.arch->types->getBase(4,TYPE_UNKNOWN));
  PcodeOp *realLoad = env.op(CPUI_LOAD,{env.fd->newVarnodeSpace(stack->getContain()),address},word);
  ASSERT_EQUALS(loadRule.applyOp(realLoad,*env.fd),0);
  PcodeOp *realStore = env.op(CPUI_STORE,{env.fd->newVarnodeSpace(stack->getContain()),address,env.constant(2,1)});
  ASSERT_EQUALS(storeRule.applyOp(realStore,*env.fd),0);
  ASSERT_EQUALS(realLoad->code(),CPUI_LOAD);
  ASSERT_EQUALS(realStore->code(),CPUI_STORE);
  // The processor-owned constant address calculation still folds normally.
  PcodeOp *fixed = env.segment(env.constant(2,0x1234),env.constant(2,0x50),env.arch->types->getBase(4,TYPE_UNKNOWN))->getDef();
  RuleSegment segmentRule("base");
  ASSERT_EQUALS(segmentRule.applyOp(fixed,*env.fd),1);
  ASSERT_EQUALS(fixed->code(),CPUI_COPY);
  ASSERT_EQUALS(fixed->getIn(0)->getOffset(),0x12340050);
}

TEST(segmented_array_address) {
  SegmentedEnvironment env;
  Datatype *word = env.arch->types->getBase(2,TYPE_UNKNOWN);
  Datatype *nearPtr = env.arch->types->getTypePointer(2,word,1);
  Datatype *farPtr = env.arch->types->getTypePointer(4,word,1);
  Varnode *offset = env.op(CPUI_PTRADD,{env.constant(2,0x1000,nearPtr),env.constant(2,3),env.constant(2,2)},nearPtr)->getOut();
  Varnode *address = env.segment(env.constant(2,0x1234),offset,farPtr);
  PcodeOp *load = env.op(CPUI_LOAD,{env.fd->newVarnodeSpace(env.arch->getDefaultDataSpace()),address},word);
  SegmentedExpressionPrinter<PrintC> printer(env.arch);
  string text = printer.expression(load);
  ASSERT_EQUALS(text.substr(0,31),"*(xunknown2 *)segmentop(0x1234,");
  ASSERT(text.find(" + 3)") != string::npos);
  ASSERT(text.find('[') == string::npos);
  PcodeOp *store = env.op(CPUI_STORE,{env.fd->newVarnodeSpace(env.arch->getDefaultDataSpace()),address,env.constant(2,7)});
  text = printer.expression(store);
  ASSERT(text.find("*(xunknown2 *)segmentop(0x1234,") == 0);
  ASSERT(text.find(" = 7") != string::npos);
  text = printer.expression(address->getDef());
  ASSERT(text.find("(xunknown2 *)segmentop(0x1234,") == 0);
  ASSERT(text.find('[') == string::npos);
  // Nonsegmented C array access, and the Java follower's own array notation, remain values rather than addresses.
  PcodeOp *plainLoad = env.op(CPUI_LOAD,{env.fd->newVarnodeSpace(env.arch->getDefaultDataSpace()),offset},word);
  text = printer.expression(plainLoad);
  ASSERT(text.find("[3]") != string::npos);
  ASSERT(text.find("segmentop") == string::npos);
  SegmentedExpressionPrinter<PrintJava> javaPrinter(env.arch);
  text = javaPrinter.expression(plainLoad);
  ASSERT(text.find("[3]") != string::npos);
  ASSERT(text.find("segmentop") == string::npos);
}

TEST(segmented_member_address) {
  SegmentedEnvironment env;
  istringstream declaration("struct SegmentedRecord { int2 first; int2 second; }");
  string name;
  Datatype *record = parse_type(declaration,name,env.arch);
  Datatype *nearPtr = env.arch->types->getTypePointer(2,record,1);
  Datatype *word = env.arch->types->getBase(2,TYPE_INT);
  Datatype *nearWord = env.arch->types->getTypePointer(2,word,1);
  Datatype *farWord = env.arch->types->getTypePointer(4,word,1);
  Varnode *offset = env.op(CPUI_PTRSUB,{env.constant(2,0x1000,nearPtr),env.constant(2,2)},nearWord)->getOut();
  Varnode *address = env.segment(env.constant(2,0x1234),offset,farWord);
  PcodeOp *load = env.op(CPUI_LOAD,{env.fd->newVarnodeSpace(env.arch->getDefaultDataSpace()),address},word);
  SegmentedExpressionPrinter<PrintC> printer(env.arch);
  string text = printer.expression(load);
  ASSERT_EQUALS(text.substr(0,27),"*(int2 *)segmentop(0x1234,&");
  ASSERT(text.find("->second)") != string::npos);
}

} // End namespace ghidra
