import Image from "next/image";
import { HeroReadMe } from "@/components/landing/hero-readme";
import { HeroTitle } from "@/components/landing/hero-title";
import { LineFieldBackground } from "@/components/landing/line-field-bg";
import { SignatureMark } from "@/components/landing/signature-mark";

export default function HomePage() {
  return (
    <div id="hero" className="relative pt-[45px] lg:pt-0">
      <div className="relative text-foreground" data-v="1">
        <div className="flex flex-col lg:flex-row">
          <div className="relative z-10 w-full border-b border-foreground/[0.06] bg-background px-5 sm:px-6 lg:sticky lg:top-0 lg:h-dvh lg:w-[40%] lg:overflow-clip lg:border-b-0 lg:border-r lg:px-7">
            <LineFieldBackground />
            <div className="pointer-events-auto absolute left-1/2 top-24 hidden w-full -translate-x-1/2 select-none items-start justify-center opacity-35 lg:flex">
              <div className="group flex w-full max-w-[300px] justify-center opacity-100 dark:hidden">
                <Image src="/left-3d-logo-light.svg" alt="" width={518} height={667} priority draggable={false} className="z-10 h-auto max-h-[140px] animate-logo-snap-left transition-transform duration-300 ease-out group-hover:-translate-x-3 group-hover:-rotate-5" />
                <Image src="/right-3d-logo-light.svg" alt="" width={518} height={667} priority draggable={false} className="-ml-28 -mt-3 h-auto max-h-[140px] animate-logo-snap-right transition-transform duration-300 ease-out group-hover:translate-x-3 group-hover:rotate-5" />
              </div>
              <div className="group hidden w-full max-w-[300px] justify-center opacity-100 dark:flex">
                <Image src="/left-3d-logo.svg" alt="" width={518} height={667} priority draggable={false} className="z-10 h-auto max-h-[140px] animate-logo-snap-left transition-transform duration-300 ease-out group-hover:-translate-x-3 group-hover:-rotate-5" />
                <Image src="/right-3d-logo.svg" alt="" width={518} height={667} priority draggable={false} className="-ml-28 -mt-3 h-auto max-h-[140px] animate-logo-snap-right transition-transform duration-300 ease-out group-hover:translate-x-3 group-hover:rotate-5" />
              </div>
            </div>
            <HeroTitle />
            <div className="absolute bottom-4 left-5 right-5 z-[3] hidden lg:block lg:left-7 lg:right-3">
              <SignatureMark />
            </div>
          </div>
          <div className="relative z-0 w-full overflow-x-hidden lg:w-[60%]">
            <div className="flex items-start justify-center lg:items-center">
              <HeroReadMe />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
